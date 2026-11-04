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
import unicodedata
from dataclasses import dataclass

# JSON Schema for the plan. Also sent as response_format json_schema when asking the model for a plan.
PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "summary", "edits", "commands", "images", "targets"],
    "properties": {
        "version": {"const": 1},
        "summary": {"type": "string"},
        "edits": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["path", "why"],
            "properties": {"path": {"type": "string"}, "why": {"type": "string"}}}},
        "commands": {"type": "array", "items": {
            "type": "array", "minItems": 1, "items": {"type": "string"}}},
        "images": {"type": "array", "items": {"type": "string"}},
        # The servers to probe inside the prove microVM: a loopback address and the server that must
        # own its port ("nginx" or a program the plan builds). At least one: a proof that probes
        # nothing proves nothing.
        "targets": {"type": "array", "minItems": 1, "items": {
            "type": "object", "additionalProperties": False, "required": ["addr", "server"],
            "properties": {"addr": {"type": "string"}, "server": {"type": "string"}}}},
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
LOOPBACK = r"127\.0\.0\.1:[1-9][0-9]{0,4}"  # servers are probed inside their own microVM
# tls_probe's own reference servers (prove.CONTROL_ADDR, prove.NEGATIVE_ADDR): never a target.
PROBE_ADDRS = frozenset({"127.0.0.1:4433", "127.0.0.1:4434"})
PROGRAMS = {
    "make": (None, TARGET),
    "go": ("build|test|vet", rf"{GO_PACKAGE}|-v|-count=1|-mod=vendor|-trimpath|-o={REL_OUT}"),
    "nginx": (None, rf"-t|-q|-c|-p|{ABS_PATH}"),
    # PQ-Proof's own fixed-version TLS client and reference server (prove.py), not repo code.
    "tls_probe": ("version|cert|serve|connect|listeners",
                  rf"-(?:groups|hosts)=[A-Za-z0-9_.,-]+|-(?:ca|cert|key)={ABS_PATH}|-servername=[A-Za-z0-9.-]+|-ports=[0-9,]+"
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


SUMMARY_MAX, WHY_MAX = 500, 300
# Control (escape sequences, CR, LF), format (bidi overrides, zero width), line and paragraph
# separators, private use, surrogates and unassigned code points.
UNPRINTABLE = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})


def check_text(value, field, limit):
    """Free text the approver reads (summary, why): one line of printable characters, bounded.
    The approval screen prints it as is, so an escape sequence could hide the lines after it."""
    if not isinstance(value, str) or len(value) > limit:
        raise PlanError(f"{field} must be a string of at most {limit} characters")
    bad = sorted({f"U+{ord(c):04X}" for c in value if unicodedata.category(c) in UNPRINTABLE})
    if bad:
        raise PlanError(f"{field} has characters that are not printable on one line: {', '.join(bad[:5])}")
    return value


def clean_text(text, limit=None):
    """Repository text on its way into a prompt: control and format characters (except tab and
    newline), private use, surrogates and unassigned code points become U+FFFD, so an escape
    sequence or a bidi override does not reach the model as it is. With a limit, the text is cut
    to that many characters and says so."""
    text = "".join("\ufffd" if c not in "\t\n" and unicodedata.category(c) in UNPRINTABLE else c for c in str(text))
    if limit is not None and len(text) > limit:
        text = text[:limit] + f"\n[... cut at {limit} characters]"
    return text


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


def check_addr(addr):
    """A server address inside the prove microVM: 127.0.0.1:PORT with PORT 1-65535, not the probe's own."""
    if not isinstance(addr, str) or not re.fullmatch(LOOPBACK, addr) or int(addr.rsplit(":", 1)[1]) > 65535:
        raise PlanError(f"target must be a loopback address inside the microVM, 127.0.0.1:PORT (1-65535): {addr!r}")
    if addr in PROBE_ADDRS:
        raise PlanError(f"target {addr} is the probe's own reference server, not a server of the repo")
    return addr


# Servers the prove step starts itself and may name as the owner of a target port, besides the
# programs the plan builds.
SERVERS = frozenset({"nginx"})


def check_target(target, built=frozenset()):
    """(addr, server): the address to probe and the server that must own its port in the microVM."""
    if not isinstance(target, dict) or set(target) != {"addr", "server"}:
        raise PlanError(f"target must have exactly 'addr' and 'server' (which server owns the port): {target!r}")
    server = target["server"]
    if not isinstance(server, str) or server not in SERVERS | built:
        raise PlanError(f"target server must be nginx or a program this plan builds ({', '.join(sorted(built)) or 'none'}): "
                        f"{server!r}")
    return check_addr(target["addr"]), server


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
    targets: frozenset = frozenset()  # (addr, server) pairs

    @property
    def addrs(self):
        return frozenset(a for a, _ in self.targets)

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
                "paths": sorted(self.paths), "images": sorted(self.images),
                "targets": [{"addr": a, "server": n} for a, n in sorted(self.targets)]}


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
        if not isinstance(plan[key], list):
            raise PlanError(f"{key} must be a list")
    check_text(plan["summary"], "summary", SUMMARY_MAX)
    paths = set()
    for edit in plan["edits"]:
        if not isinstance(edit, dict) or set(edit) != {"path", "why"}:
            raise PlanError(f"edit must have exactly 'path' and 'why': {edit!r}")
        check_text(edit["why"], "why", WHY_MAX)
        paths.add(clean_path(edit["path"]))
    built = built_programs(plan["commands"])
    targets = [check_target(t, built) for t in plan["targets"]]
    if not targets:
        raise PlanError("targets is empty: name at least one server address to probe")
    if len({a for a, _ in targets}) != len(targets):
        raise PlanError(f"targets repeat an address: {targets}")
    return Allowlist(commands=frozenset(check_command(c, built) for c in plan["commands"]),
                     paths=frozenset(paths),
                     images=frozenset(check_image(i) for i in plan["images"]),
                     targets=frozenset(targets))
