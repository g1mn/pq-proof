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


def _parse_tool_call(index, tc):
    fn = tc.get("function") or {}
    raw = fn.get("arguments")
    # Vultr's chat docs show a tool call without "id"; synthesize one so tool results can refer to it.
    call = ToolCall(id=tc.get("id") or f"call_{index}", name=fn.get("name") or "", arguments=None,
                    raw_arguments=raw if isinstance(raw, str) else ("" if raw is None else json.dumps(raw)))
    if isinstance(raw, dict):
        call.arguments = raw
        return call
    try:
        args = json.loads(raw) if raw else {}
    except (TypeError, ValueError) as e:
        call.error = f"arguments are not valid JSON: {e}"
        return call
    if not isinstance(args, dict):
        call.error = f"arguments must be a JSON object, got {type(args).__name__}"
        return call
    call.arguments = args
    return call


def parse_reply(body):
    """Turn a chat.completions response body (dict) into a Reply."""
    try:
        choice = body["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError):
        raise InferenceError("response has no choices[0].message") from None
    calls = [_parse_tool_call(i, tc) for i, tc in enumerate(message.get("tool_calls") or [])]
    return Reply(content=message.get("content"), tool_calls=calls,
                 finish_reason=choice.get("finish_reason"), usage=body.get("usage") or {},
                 model=body.get("model"), message=message)


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
    except (ValueError, AttributeError):
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
        return e.code, dict(e.headers or {}), e.read()


class Client:
    def __init__(self, api_key=None, base_url=BASE_URL, timeout=120.0, max_attempts=4,
                 backoff=1.0, send=urllib_send, sleep=time.sleep):
        self._key = api_key or os.environ.get(API_KEY_ENV)
        if not self._key:
            raise InferenceError(f"set {API_KEY_ENV} in the control plane's environment")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.timeout, self.max_attempts, self.backoff = timeout, max_attempts, backoff
        self._send, self._sleep = send, sleep

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
            try:
                status, resp_headers, body = self._send(self.url, self._headers(), data, self.timeout)
            except (OSError, http.client.HTTPException) as e:  # URLError, timeouts, resets, short reads
                if last:
                    raise self._error(f"network error after {attempt} attempts: {e}") from None
                self._sleep(self._delay(attempt, None))
                continue
            if status == 200:
                try:
                    return parse_reply(json.loads(body))
                except ValueError:
                    raise self._error("response is not JSON", status) from None
            if status in RETRY_STATUS and not last:
                self._sleep(self._delay(attempt, resp_headers))
                continue
            raise self._error(f"HTTP {status} after {attempt} attempt(s): {_error_message(body)}", status)
