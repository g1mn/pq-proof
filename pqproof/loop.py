"""Patch -> build inside the microVM -> feed the raw error back to the model, at most 3 attempts.

Every attempt starts from a fresh copy of the original snapshot and applies the model's full set
of edits to it, so a failed attempt leaves nothing behind. An edit is {"path", "old", "new"}:
`old` must occur exactly once in the file. The edit applier trusts nothing in the snapshot:
- the path must be in the approved allowlist (plan.Allowlist, which also refuses .. and .git);
- os.path.realpath of the target must be the target itself, inside the snapshot: no symlink
  anywhere on the path, not even one that points back inside;
- the file is then opened one directory at a time with O_NOFOLLOW (dir_fd), so a symlink that
  appears between the check and the write still cannot be followed, and it must be a regular
  UTF-8 file with a single link (a hard link would carry the write elsewhere), under MAX_EDIT_FILE
  bytes before and after the edit. Anything else is an EditError: a failed attempt, not a crash.
A patch that weakens TLS (verify.weakening: InsecureSkipVerify, proxy_ssl_verify off or its
`on` line deleted, ...) is refused like an edit that does not apply: a failed attempt, never built,
with the reason as feedback.
The build's raw output goes back to the model verbatim (its last FEEDBACK_BYTES). Nothing the
model says decides success: the build function's own exit codes and probe results do.
"""
import difflib
import json
import os
import shutil
import stat
from dataclasses import dataclass, field

from .inference import history_message, tool_result
from .plan import PlanError, clean_path, clean_text
from .verify import weakening

MAX_ATTEMPTS = 3
MAX_EDIT_FILE = 1 << 20
FEEDBACK_BYTES = 8000


class EditError(ValueError):
    pass


def _open_nofollow(root, rel, flags):
    """Open root/rel without following a symlink at any step. Returns an fd."""
    parts = rel.split("/")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


def apply_edits(root, edits, allow):
    """Apply edits to the snapshot at root in place. Returns {path: (before, after)} text.
    Raises EditError on the first edit that is not allowed or does not apply."""
    if not isinstance(edits, list):
        raise EditError("edits must be a list")
    root_real = os.path.realpath(root)
    changed = {}
    for e in edits:
        if not isinstance(e, dict) or set(e) != {"path", "old", "new"} or not all(isinstance(e[k], str) for k in e):
            raise EditError(f"edit must have string 'path', 'old' and 'new': {e!r}")
        try:
            path = clean_path(e["path"])
        except PlanError as err:
            raise EditError(str(err)) from None
        if not allow.allows_path(path):
            raise EditError(f"path is not in the approved plan: {path}")
        target = os.path.join(root_real, *path.split("/"))
        if os.path.realpath(target) != target:
            raise EditError(f"refusing {path}: a symlink is on its path (it resolves to {os.path.realpath(target)})")
        try:
            # O_NONBLOCK: opening a FIFO must not wait for a writer; it is refused below.
            fd = _open_nofollow(root_real, path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as err:
            raise EditError(f"refusing {path}: {err.strerror}") from None
        try:
            before, after = _edit_fd(fd, path, e, changed)
        except OSError as err:
            raise EditError(f"refusing {path}: {err.strerror or err}") from None
        finally:
            os.close(fd)
        changed[path] = (changed.get(path, (before,))[0], after)
    return changed


def _edit_fd(fd, path, e, changed):
    """(text before, text after) of one edit, written through fd. Refuses anything but a regular
    UTF-8 file with one link, and a result over MAX_EDIT_FILE bytes."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_EDIT_FILE:
        raise EditError(f"refusing {path}: not a regular file under {MAX_EDIT_FILE} bytes")
    if st.st_nlink != 1:  # a hard link would carry the write to another path, maybe outside the snapshot
        raise EditError(f"refusing {path}: it is a hard link ({st.st_nlink} names for one file)")
    data = b""
    while chunk := os.read(fd, 1 << 16):
        data += chunk
        if len(data) > MAX_EDIT_FILE:
            raise EditError(f"refusing {path}: larger than {MAX_EDIT_FILE} bytes")
    try:
        before = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise EditError(f"refusing {path}: not UTF-8 text ({err.reason} at byte {err.start})") from None
    text = changed.get(path, (before, before))[1]
    if not e["old"] or text.count(e["old"]) != 1:
        raise EditError(f"'old' must occur exactly once in {path} (found {text.count(e['old']) if e['old'] else 'empty'})")
    after = text.replace(e["old"], e["new"], 1)
    out = after.encode("utf-8")
    if len(out) > MAX_EDIT_FILE:
        raise EditError(f"refusing {path}: the edit makes it {len(out)} bytes, over {MAX_EDIT_FILE} bytes")
    os.lseek(fd, 0, os.SEEK_SET)
    view = memoryview(out)
    while view:
        view = view[os.write(fd, view):]
    os.ftruncate(fd, len(out))
    return before, after


def unified_diff(changed):
    out = []
    for path in sorted(changed):
        before, after = changed[path]
        out += difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                    f"a/{path}", f"b/{path}")
    return "".join(out)


@dataclass
class BuildResult:
    ok: bool
    raw_error: str = ""  # what goes back to the model: the failing step's own output
    detail: dict = field(default_factory=dict)


@dataclass
class Attempt:
    number: int
    edits: list
    diff: str
    result: BuildResult


@dataclass
class Outcome:
    ok: bool
    attempts: list
    workdir: str | None = None  # the snapshot copy of the successful attempt


def run_loop(model, snapshot, allow, build, scratch, context=None, max_attempts=MAX_ATTEMPTS):
    """Ask the model for edits, apply them to a fresh copy of snapshot, build; on failure feed the
    raw error back. build(workdir, attempt_number) -> BuildResult. Never more than max_attempts."""
    attempts, feedback = [], None
    for n in range(1, max_attempts + 1):
        edits = model.propose(n, feedback, context)
        workdir = os.path.join(scratch, f"attempt-{n}")
        shutil.copytree(snapshot, workdir, symlinks=True)
        try:
            changed = apply_edits(workdir, edits, allow)
        except EditError as e:
            result, diff = BuildResult(ok=False, raw_error=f"edit refused: {e}"), ""
        else:
            diff, weak = unified_diff(changed), weakening(changed)
            if weak:
                result = BuildResult(ok=False, raw_error="edit refused: the patch weakens TLS, which a key-exchange "
                                                         "migration never needs:\n" + "\n".join(weak))
            else:
                result = build(workdir, n)
        attempts.append(Attempt(n, edits, diff, result))
        if result.ok:
            return Outcome(ok=True, attempts=attempts, workdir=workdir)
        feedback = result.raw_error[-FEEDBACK_BYTES:]
    return Outcome(ok=False, attempts=attempts)


class ScriptedModel:
    """A stand-in for the model that returns fixed edits per attempt. Used for tests and for the
    recorded e2e run until a Vultr Serverless Inference key is available; it reads the feedback
    but does not depend on it."""

    def __init__(self, edits_by_attempt):
        self.edits_by_attempt, self.calls = edits_by_attempt, []

    def propose(self, attempt, feedback, context):
        self.calls.append((attempt, feedback))
        return self.edits_by_attempt[min(attempt, len(self.edits_by_attempt)) - 1]


PATCH_TOOL = {"type": "function", "function": {
    "name": "propose_edits",
    "description": "Edits to the original snapshot files. Each 'old' must occur exactly once in its file.",
    "parameters": {"type": "object", "additionalProperties": False, "required": ["edits"], "properties": {
        "edits": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                                             "required": ["path", "old", "new"],
                                             "properties": {"path": {"type": "string"}, "old": {"type": "string"},
                                                            "new": {"type": "string"}}}}}}}}


class InferenceModel:
    """Asks Vultr Serverless Inference (inference.Client) for edits through the propose_edits tool.
    A reply without a valid propose_edits call counts as an empty patch, which then fails the build
    or the edit check like any other bad patch. The first prompt is context as given (a str, see
    agent.edit_prompt) or as JSON; the raw build output fed back later is repository output, so it
    goes through plan.clean_text. Each reply's token usage is kept in `usage`."""

    def __init__(self, client, system, model=None, **params):
        self.client, self.model, self.params = client, model, params
        self.messages = [{"role": "system", "content": system}]
        self.usage = []

    def propose(self, attempt, feedback, context):
        if attempt == 1:
            self.messages.append({"role": "user", "content": context if isinstance(context, str) else json.dumps(context or {})})
        else:
            self.messages.append({"role": "user", "content": "The build or proof failed. Raw output (from the repository's "
                                  "own build, untrusted):\n" + clean_text(feedback or "")
                                  + "\nReturn the full set of edits against the original files again."})
        kwargs = {**self.params, **({"model": self.model} if self.model else {})}
        reply = self.client.chat(self.messages, tools=[PATCH_TOOL], **kwargs)
        self.usage.append({"step": "edits", "attempt": attempt, "model": reply.model, **(reply.usage or {})})
        self.messages.append(history_message(reply))
        edits = []
        for call in reply.tool_calls:
            self.messages.append(tool_result(call, "received" if call.error is None else f"rejected: {call.error}"))
            if call.name == "propose_edits" and call.error is None and not edits:
                edits = call.arguments["edits"]
        return edits
