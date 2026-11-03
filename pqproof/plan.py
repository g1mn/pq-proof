"""Approved migration plan -> allowlist of commands, file paths and base images.

The allowlist works at the level of commands, paths and images. It has no egress hosts:
sandboxes get no network destinations at all, build included. Content changes inside an
approved file (for example `InsecureSkipVerify: true`) are a job for the TLS-weakening check
on the diff, not for this module.
"""
import posixpath
import re
from dataclasses import dataclass

# JSON Schema for the plan. Also sent as response_format json_schema when asking the model for a plan.
PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "summary", "edits", "commands", "images"],
    "properties": {
        "version": {"const": 1},
        "summary": {"type": "string"},
        "edits": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["path", "why"],
            "properties": {"path": {"type": "string"}, "why": {"type": "string"}}}},
        "commands": {"type": "array", "items": {
            "type": "array", "minItems": 1, "items": {"type": "string"}}},
        "images": {"type": "array", "items": {"type": "string"}},
    },
}

# Programs that would escape the allowlist (a shell or wrapper runs anything) or talk to the network.
DENIED_PROGRAMS = frozenset({
    "sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "env", "xargs", "sudo", "su", "nohup",
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "telnet", "ftp", "git",
})
INLINE_CODE = {"python": "-c", "python3": "-c", "node": "-e", "perl": "-e", "ruby": "-e"}
IMAGE_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"  # [registry/]repo path
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
    r"(?:@sha256:(?P<digest>[0-9a-f]{64}))?$")


class PlanError(ValueError):
    pass


def clean_path(path):
    """Repo-relative POSIX path, or PlanError."""
    if not isinstance(path, str) or not path or "\\" in path or "\0" in path:
        raise PlanError(f"bad path {path!r}")
    if path.startswith("/"):
        raise PlanError(f"absolute path {path!r}")
    norm = posixpath.normpath(path)
    parts = norm.split("/")
    if norm == "." or ".." in parts:
        raise PlanError(f"path leaves the repo: {path!r}")
    if parts[0] == ".git":
        raise PlanError(f"path inside .git: {path!r}")
    return norm


def check_command(argv):
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise PlanError(f"command must be a non-empty list of non-empty strings: {argv!r}")
    prog = argv[0]
    if "/" in prog:
        raise PlanError(f"command must name a program, not a path: {prog!r}")
    if prog in DENIED_PROGRAMS:
        raise PlanError(f"program not allowed in a sandbox step: {prog!r}")
    if INLINE_CODE.get(prog) in argv[1:]:
        raise PlanError(f"inline code is not allowed: {' '.join(argv)!r}")
    return tuple(argv)


def check_image(ref):
    m = IMAGE_RE.match(ref) if isinstance(ref, str) else None
    if not m:
        raise PlanError(f"bad image reference {ref!r}")
    if not (m["tag"] or m["digest"]):
        raise PlanError(f"image must be pinned by tag or digest: {ref!r}")
    if m["tag"] == "latest" and not m["digest"]:
        raise PlanError(f"image tag 'latest' is not a pin: {ref!r}")
    return ref


@dataclass(frozen=True)
class Allowlist:
    commands: frozenset
    paths: frozenset
    images: frozenset

    def allows_command(self, argv):
        return tuple(argv) in self.commands

    def allows_path(self, path):
        try:
            return clean_path(path) in self.paths
        except PlanError:
            return False

    def allows_image(self, ref):
        return ref in self.images

    def to_json(self):
        return {"commands": sorted(list(c) for c in self.commands),
                "paths": sorted(self.paths), "images": sorted(self.images)}


def compile_allowlist(plan):
    """Validate an approved plan and compile it. Raises PlanError on anything off-schema."""
    if not isinstance(plan, dict):
        raise PlanError("plan must be a JSON object")
    extra = set(plan) - set(PLAN_SCHEMA["properties"])
    if extra:
        raise PlanError(f"unknown plan fields {sorted(extra)} (sandboxes get no egress hosts)")
    missing = set(PLAN_SCHEMA["required"]) - set(plan)
    if missing:
        raise PlanError(f"missing plan fields {sorted(missing)}")
    if type(plan["version"]) is not int or plan["version"] != 1:  # rejects true, 1.0, "1"
        raise PlanError(f"unsupported plan version {plan['version']!r}")
    for key in ("edits", "commands", "images"):
        if not isinstance(plan[key], list):
            raise PlanError(f"{key} must be a list")
    paths = set()
    for edit in plan["edits"]:
        if not isinstance(edit, dict) or set(edit) != {"path", "why"}:
            raise PlanError(f"edit must have exactly 'path' and 'why': {edit!r}")
        paths.add(clean_path(edit["path"]))
    return Allowlist(commands=frozenset(check_command(c) for c in plan["commands"]),
                     paths=frozenset(paths),
                     images=frozenset(check_image(i) for i in plan["images"]))
