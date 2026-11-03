"""Build and prove one snapshot of a repo like orders-edge (nginx in front of a Go API).

Nothing from the repo runs on the host. The repo's Dockerfile is read, never built with docker:
- build: a microVM from the Dockerfile's first FROM image (approved and pinned) gets a copy of
  the snapshot and runs the plan's `make` and `go` commands offline (vendored modules, no proxy);
  the plan's `go build -o=out/NAME` result is copied out as one regular file;
- prove: a microVM from the Dockerfile's last FROM image (the runtime) gets the snapshot, the built
  program and tls_probe; it runs `nginx -t`, starts the probe's two reference servers, then the
  built program and nginx as background jobs; the probe must pass a positive and a negative
  control, then it probes every target twice (hybrid-only client, classical client).
  The repo's servers run as unprivileged users (BUILT_USER, NGINX_USER: one uid each), so they
  cannot replace the probe, which stays root-owned; the probe binary is copied back out and
  hashed before the controls and after the last handshake. The control plane, as root, only
  creates nginx's pid file and cache directory for NGINX_USER beforehand.
Each step's raw output is what goes back to the model when it fails.
"""
import hashlib
import os
import re
import stat
from dataclasses import dataclass

from . import prove
from .loop import BuildResult
from .plan import Allowlist
from .sandbox import Limits
from .scan import dockerfile_images

SRC = "/work/src"
GO_ENV = {"CGO_ENABLED": "0", "GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOTOOLCHAIN": "local"}
BUILD_LIMITS = Limits(cpus=2, memory_mib=2048, wall_clock_s=300)
PROVE_LIMITS = Limits(cpus=1, memory_mib=1024, wall_clock_s=120)
RAW_TAIL = 6000
# The repo's servers never run as root in the prove microVM. Numeric ids, one per kind of server.
NGINX_USER = "65534:65534"
BUILT_USER = "65533:65533"
NGINX_CACHE = "/var/cache/nginx"  # temp paths of the official nginx images
GUEST_ABS = re.compile(r"(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)+")


class PipelineError(RuntimeError):
    pass


def _read_text(root, rel):
    """A snapshot file's text without following symlinks (None if absent or not a regular file)."""
    path = os.path.join(root, *rel.split("/"))
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
        return None
    with open(path, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Layout:
    nginx_conf: str  # repo-relative
    tls_dir: str  # where the config expects cert.pem, key.pem and ca.pem
    servername: str
    hosts: str  # names and IPs for the test certificate
    pid: str  # nginx's pid file, created for NGINX_USER before nginx starts


def tls_layout(root, nginx_conf="nginx/nginx.conf"):
    """Where the nginx config expects its TLS files, and the names the test certificate needs."""
    text = _read_text(root, nginx_conf)
    if text is None:
        raise PipelineError(f"no regular file at {nginx_conf}")
    files = dict(re.findall(r"^\s*(ssl_certificate|ssl_certificate_key|proxy_ssl_trusted_certificate)\s+(/\S+);", text, re.M))
    dirs = {os.path.dirname(p) for p in files.values()}
    names = {k: os.path.basename(v) for k, v in files.items()}
    if len(dirs) != 1 or names.get("ssl_certificate") != "cert.pem" or names.get("ssl_certificate_key") != "key.pem" \
            or names.get("proxy_ssl_trusted_certificate", "ca.pem") != "ca.pem":
        raise PipelineError("the prove step needs ssl_certificate cert.pem, ssl_certificate_key key.pem "
                            f"(and proxy_ssl_trusted_certificate ca.pem) in one absolute directory, found {files}")
    server = re.search(r"^\s*server_name\s+([A-Za-z0-9.-]+)", text, re.M)
    servername = server[1] if server else "localhost"
    hosts = ["localhost", "127.0.0.1", servername] + re.findall(r"^\s*proxy_ssl_name\s+([A-Za-z0-9.-]+);", text, re.M)
    pid = re.search(r"^\s*pid\s+(\S+);", text, re.M)
    if not pid or not GUEST_ABS.fullmatch(pid[1]):
        raise PipelineError("the prove step runs nginx as an unprivileged user and creates its pid file first: "
                            f"it needs a `pid /absolute/path;` directive, found {pid[1] if pid else 'none'!r}")
    return Layout(nginx_conf=nginx_conf, tls_dir=dirs.pop(), servername=servername,
                  hosts=",".join(dict.fromkeys(hosts)), pid=pid[1])


def nginx_prep(layout):
    """The control plane's fixed root commands that let nginx run as NGINX_USER."""
    uid, gid = NGINX_USER.split(":")
    return [("install", "-d", "-o", uid, "-g", gid, "-m", "0755", NGINX_CACHE),
            ("install", "-o", uid, "-g", gid, "-m", "0644", "/dev/null", layout.pid)]


def stage_images(root, allow, pins):
    """(build image, runtime image) from the snapshot's Dockerfile, as approved pinned references.
    pins maps what the model named (name:tag) to what was resolved and approved."""
    text = _read_text(root, "Dockerfile")
    if text is None:
        raise PipelineError("no regular Dockerfile in the snapshot")
    images = dockerfile_images(text)
    if not images:
        raise PipelineError("Dockerfile has no FROM line")
    out = []
    for line, image, _ in (images[0], images[-1]):
        pinned = image if allow.allows_image(image) else pins.get(image)
        if not pinned or not allow.allows_image(pinned):
            raise PipelineError(f"Dockerfile line {line}: FROM {image} is not an approved image "
                                f"(approved: {sorted(allow.images)})")
        out.append(pinned)
    return tuple(out)


def _digest(text):
    return {"bytes": getattr(text, "total", len(str(text))),
            "sha256": getattr(text, "sha256", hashlib.sha256(str(text).encode()).hexdigest())}


def _session_record(s, sinkhole=None):
    events, dropped = sinkhole.take() if sinkhole else ([], 0)
    return {"sandbox": s.name, "image": s.image, "limits": vars(s.limits), "started_at": s.started_at,
            "destroyed_at": s.destroyed_at, "host_commands": [list(c) for c in s.host_commands],
            "execs": [{"argv": e.argv, "exit_code": e.exit_code, "timed_out": e.timed_out,
                       "stdout": _digest(e.stdout), "stderr": _digest(e.stderr)} for e in s.execs],
            "egress": {"sinkhole_events": events, "uncounted": dropped,
                       "canaries": sorted({c for ev in events for c in ev["canaries"]})}}


def _hs(h):
    return {"kind": h.kind, "group": h.group, "error": h.error}


def _raw(e):
    out = (str(e.stdout) + str(e.stderr))[-RAW_TAIL:]
    return f"$ {' '.join(e.argv)}\n(exit {e.exit_code}{', timed out' if e.timed_out else ''})\n{out}"


class Pipeline:
    def __init__(self, runner, allow, probe, layout, pins, job, scratch, sinkhole=None):
        self.runner, self.allow, self.probe, self.layout = runner, allow, probe, layout
        self.pins, self.job, self.scratch, self.sinkhole = pins, job, scratch, sinkhole

    def _commands(self, program):
        return sorted((c for c in self.allow.commands if c[0] == program), key=lambda c: (len(c), c))

    def build_and_prove(self, workdir, attempt):
        """BuildResult for one snapshot copy. attempt is a label: 0 for the baseline, then 1, 2, 3."""
        detail = {"attempt": attempt}
        if not self.allow.targets:  # nothing probed is not a pass
            return BuildResult(ok=False, raw_error="the approved plan names no target address to probe", detail=detail)
        try:
            build_img, run_img = stage_images(workdir, self.allow, self.pins)
        except PipelineError as e:
            return BuildResult(ok=False, raw_error=str(e), detail=detail)
        out_dir = os.path.join(self.scratch, f"out-{attempt}")
        os.makedirs(out_dir)
        tag = f"a{attempt}"

        # build: tests first, then the build commands, in the build stage image
        builds = [c for c in self._commands("go") if c[1] == "build"]
        with self.runner.session(self.allow, self.job, f"build-{tag}", build_img, BUILD_LIMITS) as s:
            s.copy_in(workdir, SRC)
            failed = None
            for argv in self._commands("make") + [c for c in self._commands("go") if c[1] != "build"] + builds:
                e = s.exec(list(argv), env=GO_ENV, workdir=SRC)
                if e.exit_code != 0:
                    failed = e
                    break
            binaries = []
            if not failed:
                for argv in builds:
                    out = next(a[3:] for a in argv if a.startswith("-o="))
                    binaries.append(s.copy_out(f"{SRC}/{out}", out_dir))
        detail["build"] = _session_record(s, self.sinkhole)
        if failed:
            return BuildResult(ok=False, raw_error=_raw(failed), detail=detail)

        # prove: runtime image, probe, reference servers, the repo's servers, both controls, every target
        lay = self.layout
        allow = self.allow.union(prove.probe_allowlist(sorted(self.allow.targets), lay.tls_dir, lay.servername, lay.hosts))
        allow = allow.union(Allowlist(commands=frozenset(nginx_prep(lay)), paths=frozenset(), images=frozenset()))
        conf = f"{SRC}/{lay.nginx_conf}"
        verdict = {"positive_control": None, "negative_control": None, "targets": {}}
        invalid = None
        with self.runner.session(allow, self.job, f"prove-{tag}", run_img, PROVE_LIMITS) as s:
            s.copy_in(workdir, SRC)
            for path in binaries:
                s.copy_in(path, f"/usr/local/bin/{os.path.basename(path)}")
            verdict["probe"] = prove.install_probe(s, self.probe, lay.tls_dir, lay.hosts)
            for argv in nginx_prep(lay):
                e = s.exec(list(argv))
                if e.exit_code != 0:
                    failed = failed or e
            e = failed or s.exec(["nginx", "-t", "-c", conf], user=NGINX_USER)
            if e.exit_code != 0:
                failed = e
            else:
                prove.start_references(s, lay.tls_dir)  # before any repo server can take their ports
                for path in binaries:  # the plan says whether to run what it built
                    if self.allow.allows_command([os.path.basename(path)]):
                        s.start([os.path.basename(path)], user=BUILT_USER)
                s.start(["nginx", "-c", conf], user=NGINX_USER)
                invalid = prove.verify_probe(s, self.probe, os.path.join(out_dir, "probe-before"))
                if not invalid:
                    ctl = prove.controls(s, lay.tls_dir)
                    verdict["positive_control"] = _hs(ctl["positive"][0])
                    verdict["negative_control"] = {"hybrid": _hs(ctl["negative_hybrid"][0]),
                                                   "classical": _hs(ctl["negative_classical"][0])}
                    invalid = prove.control_problem(ctl)
                for target in [] if invalid else sorted(self.allow.targets):
                    res = prove.probe_target(s, target, lay.tls_dir, lay.servername)
                    verdict["targets"][target] = {k: {"kind": h.kind, "group": h.group, "error": h.error,
                                                      "exit_code": ex.exit_code} for k, (h, ex) in res.items()}
                    if failed is None and res["hybrid"][0].kind != "hybrid":
                        failed = res["hybrid"][1]
                    elif failed is None and not res["classical"][0].ok:
                        failed = res["classical"][1]
                if not invalid:
                    invalid = prove.verify_probe(s, self.probe, os.path.join(out_dir, "probe-after"))
        detail["prove"] = _session_record(s, self.sinkhole)
        detail["verdict"] = verdict
        if invalid:
            return BuildResult(ok=False, raw_error=f"proof invalid, no server was judged: {invalid}", detail=detail)
        if failed:
            return BuildResult(ok=False, raw_error=_raw(failed), detail=detail)
        return BuildResult(ok=True, detail=detail)


HOST_BUILD_PROGRAMS = {"make", "go", "nginx", "docker", "podman", "buildah", "tls_probe", "cc", "gcc"}


def host_build_count(host_argvs, msb="msb"):
    """How many host command lines ran a build or server program outside msb (must be 0)."""
    return sum(1 for argv in host_argvs if os.path.basename(argv[0]) != os.path.basename(msb)
               and os.path.basename(argv[0]) in HOST_BUILD_PROGRAMS)


def guest_commands(host_argvs, msb="msb"):
    """The command lines that ran inside microVMs: everything after `--` of each `msb exec`."""
    out = []
    for argv in host_argvs:
        if os.path.basename(argv[0]) == os.path.basename(msb) and len(argv) > 1 and argv[1] == "exec" and "--" in argv:
            out.append(argv[argv.index("--") + 1:])
    return out
