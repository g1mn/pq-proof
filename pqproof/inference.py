"""Vultr Serverless Inference client: OpenAI-compatible chat completions with tool calls.

Only the control plane imports this module. The API key comes from the environment and is
never put into messages, logs or exceptions: error text is redacted, the Authorization header
is built inside the call (not held in chat()'s locals), and redirects are not followed, so the
header cannot be carried to another origin.
"""
import http.client
import json
import math
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

BASE_URL = "https://api.vultrinference.com/v1"
API_KEY_ENV = "VULTR_INFERENCE_API_KEY"
# Defaults from the public model list (https://api.vultrinference.com/v1/models).
# Re-check that list after kickoff before a real run.
PLAN_MODEL = "glm-5.3"
SUMMARY_MODEL = "deepseek-v4.1-flash-1017"

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_DELAY_S = 30.0
# Requests one Client sends in its life (one run): a run asks for at most 3 plans and 3 sets of
# edits (agent.MAX_PLAN_ATTEMPTS, loop.MAX_ATTEMPTS), and this leaves room for 2 retries. Without
# it, 4 attempts per call made 24 billable requests possible. A request that timed out may still be
# billed, so every request counts, answered or not.
MAX_REQUESTS = 8


class InferenceError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict | None  # None when the model sent arguments that are not a JSON object
    raw_arguments: str
    error: str | None = None


@dataclass
class Reply:
    content: str | None
    tool_calls: list[ToolCall]
    finish_reason: str | None
    usage: dict = field(default_factory=dict)
    model: str | None = None
    message: dict = field(default_factory=dict)  # the assistant message, to append to history as-is


JSON_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}


def _object(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):  # json.loads would keep the last value silently
        raise ValueError(f"duplicate key in {sorted(k for k, _ in pairs)}")
    return obj


def _check_arguments(name, args, declared):
    """Why a call does not fit the tools the request declared, or None. Checks the tool name,
    required and unknown (additionalProperties: false) arguments and top-level JSON types."""
    if declared is None:
        return None
    if name not in declared:
        return f"tool {name!r} was not declared in this request"
    schema = declared[name] or {}
    props = schema.get("properties") or {}
    missing = [k for k in schema.get("required") or [] if k not in args]
    if missing:
        return f"missing required arguments {missing}"
    unknown = sorted(set(args) - set(props))
    if unknown and schema.get("additionalProperties") is False:
        return f"unknown arguments {unknown}"
    for key, value in args.items():
        kind = (props.get(key) or {}).get("type")
        want = JSON_TYPES.get(kind)
        if want and (not isinstance(value, want) or (isinstance(value, bool) and want is not bool)):
            return f"argument {key!r} must be {kind}"
    return None


def _parse_tool_call(index, tc, declared):
    fn = tc["function"]
    raw, cid, name = fn.get("arguments"), tc.get("id"), fn.get("name")
    # Vultr's chat docs show a tool call without "id"; synthesize one so tool results can refer to it.
    call = ToolCall(id=cid if isinstance(cid, str) and cid else f"call_{index}",
                    name=name if isinstance(name, str) else "", arguments=None,
                    raw_arguments=raw if isinstance(raw, str) else ("" if raw is None else json.dumps(raw)))
    if isinstance(raw, dict):
        args = raw
    else:
        try:
            args = json.loads(raw, object_pairs_hook=_object) if raw else {}
        except (TypeError, ValueError, RecursionError) as e:
            call.error = f"arguments are not valid JSON: {e}"
            return call
    if not isinstance(args, dict):
        call.error = f"arguments must be a JSON object, got {type(args).__name__}"
        return call
    call.error = _check_arguments(call.name, args, declared)
    if call.error is None:
        call.arguments = args
    return call


def parse_reply(body, tools=None):
    """Turn a chat.completions response body (dict) into a Reply. Raises InferenceError only.

    The model's output can be steered by a prompt injection in the target repo, so it is not
    trusted: with `tools`, a call to an undeclared tool or with arguments outside its parameters
    comes back with `error` set and `arguments` None. Call ids are made unique strings, and
    Reply.message carries those ids so the history matches the tool results.
    """
    try:
        choice = body["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError):
        raise InferenceError("response has no choices[0].message") from None
    if not isinstance(choice, dict) or not isinstance(message, dict):
        raise InferenceError("choices[0].message must be a JSON object")
    raw_calls = message.get("tool_calls") or []
    if not isinstance(raw_calls, list) or not all(
            isinstance(tc, dict) and isinstance(tc.get("function"), dict) for tc in raw_calls):
        raise InferenceError("tool_calls must be a list of objects, each with a function object")
    declared = None if tools is None else {t["function"]["name"]: t["function"].get("parameters") for t in tools}
    calls, seen = [], set()
    for i, tc in enumerate(raw_calls):
        try:
            call = _parse_tool_call(i, tc, declared)
        except RecursionError:  # arguments sent as a deeply nested object
            call = ToolCall(id=f"call_{i}", name="", arguments=None, raw_arguments="", error="arguments nest too deeply")
        while call.id in seen:
            call.id += "_"
        seen.add(call.id)
        calls.append(call)
    if raw_calls:
        message = {**message, "tool_calls": [{**tc, "id": c.id} for tc, c in zip(raw_calls, calls)]}
    return Reply(content=message.get("content"), tool_calls=calls,
                 finish_reason=choice.get("finish_reason"), usage=body.get("usage") or {},
                 model=body.get("model"), message=message)


def history_message(reply):
    """The assistant message to append to the conversation: role, content and tool calls only, so
    server-specific fields (reasoning text, for one) are not sent back."""
    msg = {"role": "assistant", "content": reply.message.get("content")}
    if reply.message.get("tool_calls"):
        msg["tool_calls"] = reply.message["tool_calls"]
    return msg


def tool_result(call, content):
    """Message that answers one tool call."""
    return {"role": "tool", "tool_call_id": call.id, "content": content}


def _error_message(body):
    try:
        err = json.loads(body).get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)
        if err:
            return str(err)
    except (ValueError, AttributeError, RecursionError):  # not JSON, not an object, or nested too deeply
        pass
    return body[:200].decode(errors="replace") if isinstance(body, bytes) else str(body)[:200]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # the 3xx comes back as an HTTP error instead of being followed


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_send(url, headers, data, timeout):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        with e:  # an HTTPError holds the open response
            return e.code, dict(e.headers or {}), e.read()


STDIN_NAMES = ("-", "/dev/stdin")


def key_from_file(path):
    """The API key from an env file's `VULTR_INFERENCE_API_KEY=...` line (`export ` and quotes
    allowed). path may be - or /dev/stdin, so a root-only key file can reach an unprivileged control
    plane as `< /etc/pqproof/inference.env` without entering any process environment. Standard input
    is read from file descriptor 0 itself: on Linux, opening /dev/stdin opens /proc/self/fd/0 by
    path, which checks the key file's permissions again and fails for the unprivileged user. After
    that read, fd 0 is /dev/null: left open there, the key file would pass to every child process
    started without stdin=, which can seek it back to the start and read the key (VX1 review)."""
    if str(path) in STDIN_NAMES:
        with os.fdopen(os.dup(0), encoding="utf-8") as f:
            text = f.read()
        null = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(null, 0)
        finally:
            os.close(null)
    else:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    for line in text.splitlines():
        name, sep, value = line.strip().removeprefix("export ").partition("=")
        if sep and name.strip() == API_KEY_ENV and value.strip().strip("'\""):
            return value.strip().strip("'\"")
    raise InferenceError(f"no {API_KEY_ENV}=... line in {path}")


def parse_rates(models):
    """{model id: (USD per prompt token, USD per completion token)} from a /v1/models body."""
    out = {}
    for m in (models or {}).get("data") or []:
        try:
            out[m["id"]] = (float(m["input_modalities"][0]["pricing"][0]["cost_usd"]),
                            float(m["output_modalities"][0]["pricing"][0]["cost_usd"]))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out


def fetch_rates(base_url=BASE_URL, timeout=30.0):
    """parse_rates of the public model list. No key is sent: the list needs none."""
    with _OPENER.open(urllib.request.Request(base_url.rstrip("/") + "/models"), timeout=timeout) as r:
        return parse_rates(json.loads(r.read()))


class Client:
    """One run's connection to the API. `requests` records every HTTP request sent, with its status
    (None when no response came back, a timeout say), its error and its usage (None without a
    reply), so a run's report can count what was sent, not only what was answered. At most
    max_requests are sent in all; after that chat() raises InferenceError without sending."""

    def __init__(self, api_key=None, base_url=BASE_URL, timeout=120.0, max_attempts=4,
                 backoff=1.0, send=urllib_send, sleep=time.sleep, max_requests=MAX_REQUESTS):
        self._key = api_key or os.environ.get(API_KEY_ENV)
        if not self._key:
            raise InferenceError(f"set {API_KEY_ENV} in the control plane's environment")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.timeout, self.max_attempts, self.backoff = timeout, max_attempts, backoff
        self.max_requests, self.requests = max_requests, []
        self._send, self._sleep = send, sleep

    def _record(self, model, status, error=None, usage=None):
        self.requests.append({"model": model, "status": status,
                              "error": None if error is None else error.replace(self._key, "***")[:300],
                              "usage": usage})

    def _headers(self):
        return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}

    def _error(self, message, status=None):
        return InferenceError(message.replace(self._key, "***"), status)

    def _delay(self, attempt, headers):
        retry_after = {k.lower(): v for k, v in (headers or {}).items()}.get("retry-after")
        try:
            delay = float(retry_after)
        except (TypeError, ValueError):
            delay = math.nan
        if not math.isfinite(delay):  # absent, a date, NaN or inf: exponential backoff
            delay = self.backoff * 2 ** (attempt - 1)
        return min(max(delay, 0.0), MAX_DELAY_S)

    def chat(self, messages, *, model=PLAN_MODEL, tools=None, **params):
        """POST /chat/completions. `tool_choice` is never sent: the model list does not show it."""
        payload = {"model": model, "messages": messages, **params}
        if tools:
            payload["tools"] = tools
        data = json.dumps(payload).encode()
        for attempt in range(1, self.max_attempts + 1):
            last = attempt == self.max_attempts
            if self.max_requests is not None and len(self.requests) >= self.max_requests:
                raise self._error(f"request limit reached: this run has sent {len(self.requests)} requests "
                                  f"(at most {self.max_requests})")
            try:
                status, resp_headers, body = self._send(self.url, self._headers(), data, self.timeout)
            except (OSError, http.client.HTTPException) as e:  # URLError, timeouts, resets, short reads
                self._record(model, None, f"{type(e).__name__}: {e}")
                if last:
                    raise self._error(f"network error after {attempt} attempts: {e}") from None
                self._sleep(self._delay(attempt, None))
                continue
            if status == 200:
                try:
                    reply = parse_reply(json.loads(body), tools)
                except (ValueError, RecursionError):
                    self._record(model, status, "response is not JSON (or nests too deeply)")
                    raise self._error("response is not JSON (or nests too deeply)", status) from None
                except InferenceError as e:
                    self._record(model, status, str(e))
                    raise
                self._record(model, status, usage=reply.usage or None)
                return reply
            self._record(model, status, f"HTTP {status}: {_error_message(body)}")
            if status in RETRY_STATUS and not last:
                self._sleep(self._delay(attempt, resp_headers))
                continue
            raise self._error(f"HTTP {status} after {attempt} attempt(s): {_error_message(body)}", status)
