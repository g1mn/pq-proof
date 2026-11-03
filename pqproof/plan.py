"""Approved migration plan -> allowlist of commands, file paths and base images.

The allowlist works at the level of commands, paths and images. It has no egress hosts:
sandboxes get no network destinations at all, build included. Content changes inside an
approved file (for example `InsecureSkipVerify: true`) are a job for the TLS-weakening check
on the diff, not for this module.

Paths are checked as strings. A symlink committed in the target repo can still point an allowed
path outside the snapshot, so the code that applies edits has to resolve each path and refuse
anything that leaves the snapshot root (or open it with O_NOFOLLOW).
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
        # Optional: loopback addresses of the servers to probe inside the prove microVM.
        "targets": {"type": "array", "items": {"type": "string"}},
    },
}

# The programs a plan may run, and what their arguments may look like: (pattern for the first
# argument or None, pattern for every other argument). Anything else is refused, including flags
# that run another program or inline code (go -exec/-toolexec, make --eval, -f and VAR=value,
# nginx -g). This bounds what the model can ask for. It does not make the repo's own code safe:
# `make test` runs Makefile recipes with /bin/sh and `go test` runs test code. That code runs only
# inside the microVM, with egress denied.
TARGET = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
GO_PACKAGE = r"\.(?:/[A-Za-z0-9_.-]+)*(?:/\.\.\.)?"  # ., ./..., ./cmd/api
ABS_PATH = r"(?:/[A-Za-z0-9_.-]+)+"
SEGMENT = r"[A-Za-z0-9_-][A-Za-z0-9_.-]*"  # never "." or "..", never hidden
REL_OUT = rf"(?:{SEGMENT}/)*{SEGMENT}"  # go build -o=out/api: inside the work tree
LOOPBACK = r"127\.0\.0\.1:[0-9]{1,5}"  # servers are probed inside their own microVM
PROGRAMS = {
    "make": (None, TARGET),
    "go": ("build|test|vet", rf"{GO_PACKAGE}|-v|-count=1|-mod=vendor|-trimpath|-o={REL_OUT}"),
    "nginx": (None, rf"-t|-q|-c|-p|{ABS_PATH}"),
    # PQ-Proof's own fixed-version TLS client and reference server (prove.py), not repo code.
    "tls_probe": ("version|cert|serve|connect",
                  rf"-(?:groups|hosts)=[A-Za-z0-9_.,-]+|-(?:ca|cert|key)={ABS_PATH}|-servername=[A-Za-z0-9.-]+"
                  rf"|-addr={LOOPBACK}|-wait=[0-9]{{1,3}}s|{LOOPBACK}|{ABS_PATH}"),
}
# A plan may also run, by name, a program it builds itself with `go build -o=out/NAME` (the
# server it is about to prove), with flag-style arguments only. It runs inside the microVM.
BUILT_ARG = r"-[a-z][a-z0-9-]*=[A-Za-z0-9_.,:/-]+"
# A built program named like a system tool would read to the approver as that tool.
RESERVED_NAMES = frozenset({"sh", "bash", "dash", "zsh", "env", "busybox", "sudo", "su", "python", "python3",
                            "perl", "ruby", "node", "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "git",
                            "docker", "msb", "openssl"})
PATH_CHARS = re.compile(r"[A-Za-z0-9._/-]+")
# Base images: Docker Hub official images pinned by digest, `name[:tag]@sha256:<64 hex>`. A tag
# alone is not a pin (the registry owner can move it); it may stay next to the digest for the
# approver to read. Other registries are refused, so a look-alike name cannot slip in.
IMAGE_RE = re.compile(
    r"(?P<repo>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}")
OFFICIAL = re.compile(r"(?:docker\.io/library/|library/)?[a-z0-9]+(?:[._-][a-z0-9]+)*")


class PlanError(ValueError):
    pass


def clean_path(path):
    """Repo-relative POSIX path, or PlanError."""
    if not isinstance(path, str) or not path:
        raise PlanError(f"bad path {path!r}")
    if not PATH_CHARS.fullmatch(path):  # no control characters for logs, no Unicode look-alikes
        raise PlanError(f"path has characters outside [A-Za-z0-9._/-]: {path!r}")
    if path.startswith("/"):
        raise PlanError(f"absolute path {path!r}")
    norm = posixpath.normpath(path)
    parts = norm.split("/")
    if norm == "." or ".." in parts:
        raise PlanError(f"path leaves the repo: {path!r}")
    if any(p.casefold() == ".git" for p in parts):  # any depth, any case (APFS ignores case)
        raise PlanError(f"path inside .git: {path!r}")
    return norm


def built_programs(commands):
    """Names of the programs a plan builds: the last segment of each `go build -o=PATH`."""
    names = set()
    for argv in commands:
        if isinstance(argv, list) and argv[:2] == ["go", "build"]:
            for arg in argv[2:]:
                if isinstance(arg, str) and arg.startswith("-o="):
                    name = arg[3:].rsplit("/", 1)[-1]
                    if name in PROGRAMS or name in RESERVED_NAMES or not re.fullmatch(TARGET, name):
                        raise PlanError(f"go build output must not shadow an allowed program: {arg!r}")
                    names.add(name)
    return frozenset(names)


def check_command(argv, built=frozenset()):
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise PlanError(f"command must be a non-empty list of non-empty strings: {argv!r}")
    prog = argv[0]
    if "/" in prog:
        raise PlanError(f"command must name a program, not a path: {prog!r}")
    if prog in built:
        for arg in argv[1:]:
            if not re.fullmatch(BUILT_ARG, arg):
                raise PlanError(f"argument not allowed for the built program {prog}: {arg!r}")
        return tuple(argv)
    if prog not in PROGRAMS:
        raise PlanError(f"program not allowed in a sandbox step: {prog!r} (allowed: {', '.join(PROGRAMS)})")
    first, rest = PROGRAMS[prog]
    args = argv[1:]
    if first:
        if not args or not re.fullmatch(first, args[0]):
            raise PlanError(f"{prog} subcommand not allowed: {args[:1]!r} (allowed: {first})")
        args = args[1:]
    for arg in args:
        if not re.fullmatch(rest, arg):
            raise PlanError(f"argument not allowed for {prog}: {arg!r}")
    return tuple(argv)


def check_image(ref):
    m = IMAGE_RE.fullmatch(ref) if isinstance(ref, str) else None
    if not m:
        raise PlanError(f"image must be pinned by digest, name[:tag]@sha256:<64 hex>: {ref!r}")
    if not OFFICIAL.fullmatch(m["repo"]):
        raise PlanError(f"image must be a Docker Hub official image: {ref!r}")
    return ref


@dataclass(frozen=True)
class Allowlist:
    commands: frozenset
    paths: frozenset
    images: frozenset
    targets: frozenset = frozenset()

    def allows_command(self, argv):
        return tuple(argv) in self.commands

    def allows_path(self, path):
        try:
            return clean_path(path) in self.paths
        except PlanError:
            return False

    def allows_image(self, ref):
        return ref in self.images

    def union(self, other):
        """Both allowlists together: for adding the control plane's own fixed commands (the probe)."""
        return Allowlist(commands=self.commands | other.commands, paths=self.paths | other.paths,
                         images=self.images | other.images, targets=self.targets | other.targets)

    def to_json(self):
        return {"commands": sorted(list(c) for c in self.commands),
                "paths": sorted(self.paths), "images": sorted(self.images), "targets": sorted(self.targets)}


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
    for key in ("edits", "commands", "images", "targets"):
        if not isinstance(plan.get(key, []), list):
            raise PlanError(f"{key} must be a list")
    paths = set()
    for edit in plan["edits"]:
        if not isinstance(edit, dict) or set(edit) != {"path", "why"}:
            raise PlanError(f"edit must have exactly 'path' and 'why': {edit!r}")
        paths.add(clean_path(edit["path"]))
    for target in plan.get("targets", []):
        if not isinstance(target, str) or not re.fullmatch(LOOPBACK, target):
            raise PlanError(f"target must be a loopback address inside the microVM, 127.0.0.1:PORT: {target!r}")
    built = built_programs(plan["commands"])
    return Allowlist(commands=frozenset(check_command(c, built) for c in plan["commands"]),
                     paths=frozenset(paths),
                     images=frozenset(check_image(i) for i in plan["images"]),
                     targets=frozenset(plan.get("targets", [])))
