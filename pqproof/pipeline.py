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
  creates nginx's pid file and cache directory for NGINX_USER beforehand, with /usr/bin/install
  named by its absolute path. The programs the plan built go to BUILT_DIR, which is not on the
  guest's PATH, and start by absolute path: a built program can never stand in for a command the
  control plane runs as root by name (the VX1 review built one called `install`, which then ran as
  root and replaced /usr/sbin/nginx). The only programs root runs by name are tls_probe, a name no
  plan may build, and what the runtime image itself ships.
  Each target names the server that must own its port; before any handshake, `tls_probe
  listeners` shows which process (uid and executable) holds each port, and the same listing is
  taken again after the last handshake. A server answering on another server's port is a failed
  attempt, and the servers' own output goes back with it.
Each step's raw output is what goes back to the model when it fails.
"""
import hashlib
import os
import re
import stat
from dataclasses import dataclass

from . import prove
from .loop import BuildResult, _open_nofollow
from .plan import Allowlist
from .sandbox import Limits
from .scan import dockerfile_images

SRC = "/work/src"
GO_ENV = {"CGO_ENABLED": "0", "GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOTOOLCHAIN": "local"}
BUILD_LIMITS = Limits(cpus=2, memory_mib=2048, wall_clock_s=300)
# The prove microVM gets 2 vCPUs. On the x86_64 VX1 host (msb 0.7.13), `msb copy` out of a 1 vCPU
# microVM failed every plain copy of the 7.8 MB probe (16 of 16, with 1 GiB and with 2 GiB of memory)
# with "unknown filesystem read session", while all copies from a 2 vCPU microVM worked (16 of 16).
# The proof copies the probe out twice, so on 1 vCPU every proof there ended "proof invalid".
PROVE_LIMITS = Limits(cpus=2, memory_mib=1024, wall_clock_s=120)
RAW_TAIL = 6000
# The repo's servers never run as root in the prove microVM. Numeric ids, one per kind of server.
NGINX_USER = "65534:65534"
BUILT_USER = "65533:65533"
NGINX_CACHE = "/var/cache/nginx"  # temp paths of the official nginx images
NGINX_EXE = "/usr/sbin/nginx"  # the official nginx images' binary (Debian and Alpine variants)
# Where the prove microVM gets the programs the plan built: not on the guest's PATH, which was
# /.msb/scripts:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin as root in msb 0.7.13
# microVMs from nginx:1.28-bookworm and alpine:3 (measured 11-04). `msb copy` of a file into a missing
# directory fails; a directory copy creates the missing parents (755) and keeps the directory's mode.
BUILT_DIR = "/opt/pqproof/bin"
# The control plane's own root command, by absolute path: coreutils' in nginx:1.28-bookworm, a busybox
# link in alpine:3 (measured 11-04).
INSTALL = "/usr/bin/install"
JOB_LOG_LINES = 50
JOB_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
GUEST_ABS = re.compile(r"(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)+")


class PipelineError(RuntimeError):
    pass


def _read_text(root, rel):
    """A snapshot file's text without following a symlink anywhere on its path, the directories
    included (None if absent, not a regular file or over 1 MiB). Its text can reach the model."""
    try:
        fd = _open_nofollow(os.path.realpath(root), rel, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
            return None
        return f.read(1 << 20).decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Layout:
    nginx_conf: str  # repo-relative
    tls_dir: str  # where the config expects cert.pem, key.pem and ca.pem
    servername: str
    hosts: str  # names and IPs for the test certificate
    pid: str  # nginx's pid file, created for NGINX_USER before nginx starts


NGINX_CONF = "nginx/nginx.conf"


def runtime_problems(plan, nginx_conf=NGINX_CONF):
    """Why the plan's prove commands are not what the prove step runs: a list, empty when they are.
    The prove step does not run the Dockerfile: the repository stays at SRC, nginx gets `-t -c` and
    `-c` with the repository's own config there, and a built program is started only when it is
    listed alone, as [NAME], so it runs with its own defaults. A plan that says otherwise would pass
    approval and then fail in the microVM, so the planner hears every reason first."""
    conf = f"{SRC}/{nginx_conf}"
    commands = [c for c in plan.get("commands") or [] if isinstance(c, list)]
    out = []
    for argv in commands:
        if argv[:1] == ["nginx"] and argv[-1] != conf:
            out.append(f"{' '.join(map(str, argv))}: the prove step does not run the Dockerfile; the repository stays "
                       f"at {SRC}, so nginx runs the repository's config as {conf}")
    for want in (["nginx", "-t", "-c", conf], ["nginx", "-c", conf]):
        if want not in commands:
            out.append(f"list {want}: the prove step checks and then starts nginx with the repository's config")
    for t in plan.get("targets") or []:
        server = t.get("server") if isinstance(t, dict) else None
        if isinstance(server, str) and server != "nginx" and [server] not in commands:
            out.append(f"target {t.get('addr')} is served by {server}: list [\"{server}\"] by itself; the prove step "
                       f"starts a built program only from that command, with no arguments, so it uses its own defaults "
                       f"(the TLS files sit where the nginx config's ssl_certificate lines say)")
    return out


def tls_layout(root, nginx_conf=NGINX_CONF):
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
    return [(INSTALL, "-d", "-o", uid, "-g", gid, "-m", "0755", NGINX_CACHE),
            (INSTALL, "-o", uid, "-g", gid, "-m", "0644", "/dev/null", layout.pid)]


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


def owner_problems(lines, targets):
    """(problems with the probe's reference ports, problems with the targets' ports): a port must be
    held, by at least one process, and only by the server named for it (uid and executable).
    lines come from prove.listeners; targets are (addr, server) pairs."""
    want = {prove.port(a): (a, "tls_probe", "0", prove.GUEST_PROBE, "ref") for a, _ in prove.REFERENCES}
    for addr, server in targets:
        user, exe = (NGINX_USER, NGINX_EXE) if server == "nginx" else (BUILT_USER, f"{BUILT_DIR}/{server}")
        want[prove.port(addr)] = (addr, server, user.split(":")[0], exe, "target")
    out = {"ref": [], "target": []}
    for port, (addr, server, uid, exe, kind) in sorted(want.items()):
        held = [ln["line"] for ln in lines if ln["port"] == port]
        if not held or any(ln["uid"] != uid or ln["exe"] != exe for ln in lines if ln["port"] == port):
            out[kind].append(f"{addr} must be served by {server} (uid {uid}, {exe}); listening on port {port}:\n  "
                             + ("\n  ".join(held) or "nothing"))
    return out["ref"], out["target"]


def _job_logs(s, jobs):
    out = []
    for argv, job in jobs:
        log = s.logs(job, tail=JOB_LOG_LINES) if JOB_ID.fullmatch(str(job)) else "(no job id)"
        out.append(f"$ {' '.join(argv)} (background job, last {JOB_LOG_LINES} lines)\n{str(log)[-RAW_TAIL // 2:]}")
    return "\n".join(out)


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
        bin_dir = os.path.join(out_dir, "bin")  # goes into the prove microVM as BUILT_DIR, mode and all
        os.makedirs(bin_dir)
        os.chmod(bin_dir, 0o755)
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
                    binaries.append(s.copy_out(f"{SRC}/{out}", bin_dir))
                    os.chmod(binaries[-1], 0o755)  # run by BUILT_USER in the prove microVM
        detail["build"] = _session_record(s, self.sinkhole)
        if failed:
            return BuildResult(ok=False, raw_error=_raw(failed), detail=detail)

        # prove: runtime image, probe, reference servers, the repo's servers, both controls, every target
        lay = self.layout
        targets = sorted(self.allow.targets)
        addrs = [a for a, _ in targets]
        allow = self.allow.union(prove.probe_allowlist(addrs, lay.tls_dir, lay.servername, lay.hosts))
        # the built programs the plan runs as [NAME] start as [BUILT_DIR/NAME]
        started = [os.path.basename(p) for p in binaries if self.allow.allows_command([os.path.basename(p)])]
        own = set(nginx_prep(lay)) | {(f"{BUILT_DIR}/{name}",) for name in started}
        allow = allow.union(Allowlist(commands=frozenset(own), paths=frozenset(), images=frozenset()))
        conf = f"{SRC}/{lay.nginx_conf}"
        verdict = {"positive_control": None, "negative_control": None, "listeners": None, "targets": {}}
        invalid = wrong_owner = None
        with self.runner.session(allow, self.job, f"prove-{tag}", run_img, PROVE_LIMITS) as s:
            s.copy_in(workdir, SRC)
            if binaries:
                s.copy_in(bin_dir, BUILT_DIR)
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
                jobs = []
                for name in started:  # the plan says whether to run what it built
                    argv = [f"{BUILT_DIR}/{name}"]
                    jobs.append((argv, s.start(argv, user=BUILT_USER)))
                jobs.append((["nginx", "-c", conf], s.start(["nginx", "-c", conf], user=NGINX_USER)))
                invalid = prove.verify_probe(s, self.probe, os.path.join(out_dir, "probe-before"))
                if not invalid:  # who holds each port, before any handshake
                    _, before = prove.listeners(s, addrs)
                    verdict["listeners"] = [ln["line"] for ln in before]
                    ref, tgt = owner_problems(before, targets)
                    invalid = "\n".join(ref) or None
                    if tgt and not invalid:
                        wrong_owner = "\n".join(tgt) + "\n" + _job_logs(s, jobs)
                if not invalid and not wrong_owner:
                    ctl = prove.controls(s, lay.tls_dir)
                    verdict["positive_control"] = _hs(ctl["positive"][0])
                    verdict["negative_control"] = {"hybrid": _hs(ctl["negative_hybrid"][0]),
                                                   "classical": _hs(ctl["negative_classical"][0])}
                    invalid = prove.control_problem(ctl)
                for target in [] if invalid or wrong_owner else addrs:
                    res = prove.probe_target(s, target, lay.tls_dir, lay.servername)
                    verdict["targets"][target] = {k: {"kind": h.kind, "group": h.group, "error": h.error,
                                                      "exit_code": ex.exit_code} for k, (h, ex) in res.items()}
                    if failed is None and res["hybrid"][0].kind != "hybrid":
                        failed = res["hybrid"][1]
                    elif failed is None and not res["classical"][0].ok:
                        failed = res["classical"][1]
                if not invalid and not wrong_owner:
                    _, after = prove.listeners(s, addrs)
                    if [ln["line"] for ln in after] != verdict["listeners"]:
                        invalid = ("listening sockets changed during the proof:\nbefore:\n  " + "\n  ".join(verdict["listeners"])
                                   + "\nafter:\n  " + "\n  ".join(ln["line"] for ln in after))
                if not invalid:
                    invalid = prove.verify_probe(s, self.probe, os.path.join(out_dir, "probe-after"))
        detail["prove"] = _session_record(s, self.sinkhole)
        detail["verdict"] = verdict
        if invalid:
            return BuildResult(ok=False, raw_error=f"proof invalid, no server was judged: {invalid}", detail=detail)
        if wrong_owner:
            return BuildResult(ok=False, raw_error=f"port check failed, no server was judged:\n{wrong_owner}", detail=detail)
        if failed:
            return BuildResult(ok=False, raw_error=_raw(failed), detail=detail)
        return BuildResult(ok=True, detail=detail)


HOST_BUILD_PROGRAMS = {"make", "go", "nginx", "docker", "podman", "buildah", "tls_probe", "cc", "gcc"}


# Programs that run another program given in their arguments, and interpreters that run code
# given as an argument (sh -c "make test"). Either one in front of a build program still counts.
HOST_WRAPPERS = {"env", "xcrun", "nice", "timeout", "sudo", "doas", "nohup", "time", "command", "exec", "stdbuf",
                 "ionice", "caffeinate", "arch", "xargs", "script"}
HOST_INTERPRETER = re.compile(r"(?:sh|bash|dash|zsh|ksh|fish|python[0-9.]*|perl|ruby|node)")
BUILD_WORD = re.compile(r"(?<![\w.-])(?:[\w.-]*/)*(?:" + "|".join(sorted(HOST_BUILD_PROGRAMS)) + r")(?![\w.-])")


def _runs_build(argv):
    prog = os.path.basename(argv[0]) if argv else ""
    if prog in HOST_BUILD_PROGRAMS:
        return True
    if prog in HOST_WRAPPERS:  # fail closed: any argument that names a build program
        return any(os.path.basename(a) in HOST_BUILD_PROGRAMS or _runs_build(argv[i + 1:])
                   for i, a in enumerate(argv[1:]) if os.path.basename(a) in HOST_WRAPPERS | HOST_BUILD_PROGRAMS
                   or HOST_INTERPRETER.fullmatch(os.path.basename(a)))
    if HOST_INTERPRETER.fullmatch(prog):
        return any(BUILD_WORD.search(a) for a in argv[1:])
    return False


def host_build_count(host_argvs, msb="msb"):
    """How many host command lines ran a build or server program outside msb (must be 0), directly
    or through a wrapper (env go build, sh -c "make test", python3 -c "os.system('go build')")."""
    return sum(1 for argv in host_argvs if argv and os.path.basename(argv[0]) != os.path.basename(msb) and _runs_build(argv))


def guest_commands(host_argvs, msb="msb"):
    """The command lines that ran inside microVMs: everything after `--` of each `msb exec`."""
    out = []
    for argv in host_argvs:
        if os.path.basename(argv[0]) == os.path.basename(msb) and len(argv) > 1 and argv[1] == "exec" and "--" in argv:
            out.append(argv[argv.index("--") + 1:])
    return out
