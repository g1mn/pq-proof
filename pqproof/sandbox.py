"""Run each step in a fresh Microsandbox microVM through the `msb` CLI.

Three layers keep a step bounded and leave nothing behind:
1. `msb create --max-duration`: the runtime kills the microVM at the wall clock.
2. A host-side timeout on `msb exec`, then `msb rm --force` in a finally block.
3. A reaper loop that removes any pqproof-labelled sandbox past its lifetime, so a crashed
   control plane cannot leave microVMs running.
A step runs only an image and a command line that its approved allowlist (plan.Allowlist)
holds; the runner checks this itself before it calls msb. Egress is denied for every step (see
egress.py). Every msb command line is kept in StepResult.host_commands for the receipt.
"""
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field

MSB = os.environ.get("PQPROOF_MSB", "msb")
LABEL = "app=pqproof"
GRACE_S = 5
KEEP = 1 << 20  # bytes kept of each output stream: its first and last 512 KiB
DRAIN_S = 5
NAME_PART = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
log = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    pass


class Captured(str):
    """One output stream as text: all of it, or its first and last KEEP // 2 bytes with a marker
    between them. `total` and `sha256` describe every byte the process wrote to the stream."""
    total = 0
    sha256 = hashlib.sha256().hexdigest()


# The longest wall clock any step may ask for. The reaper's default age is above it, so it never
# removes a sandbox that is still within its lifetime.
MAX_WALL_CLOCK_S = 300
REAP_GRACE_S = 60


@dataclass(frozen=True)
class Limits:
    cpus: int = 1
    memory_mib: int = 1024
    wall_clock_s: int = 120

    def __post_init__(self):
        if not 1 <= self.wall_clock_s <= MAX_WALL_CLOCK_S:
            raise ValueError(f"wall_clock_s must be 1..{MAX_WALL_CLOCK_S}, got {self.wall_clock_s}")


@dataclass
class StepResult:
    name: str
    image: str
    argv: list
    limits: Limits
    started_at: float
    exit_code: int | None = None
    stdout: str = Captured("")
    stderr: str = Captured("")
    timed_out: bool = False
    destroyed_at: float | None = None
    host_commands: list = field(default_factory=list)


def msb_env():
    """PATH, HOME and msb's own MSB_* settings. msb passes its environment on to each sandbox's
    VMM process, which lives as long as the microVM, so control-plane secrets such as the
    inference API key must not be in it."""
    return {k: v for k, v in os.environ.items() if k in ("PATH", "HOME") or k.startswith("MSB_")}


def captured(head, tail=b"", total=None, sha256=None):
    """Captured text from kept bytes. Without total and sha256, head + tail is the whole stream."""
    head, tail = bytes(head), bytes(tail)
    total = len(head) + len(tail) if total is None else total
    omitted = total - len(head) - len(tail)
    if omitted > 0:
        text = f"{head.decode(errors='replace')}\n[... {omitted} bytes not kept ...]\n{tail.decode(errors='replace')}"
    else:
        text = (head + tail).decode(errors="replace")
    out = Captured(text)
    out.total, out.sha256 = total, sha256 or hashlib.sha256(head + tail).hexdigest()
    return out


class _Drain:
    """Reads one pipe in a thread: keeps its first and last KEEP // 2 bytes, counts and hashes all."""

    def __init__(self, pipe):
        self.head, self.tail, self.total, self.hash = bytearray(), bytearray(), 0, hashlib.sha256()
        self.thread = threading.Thread(target=self._read, args=(pipe,), daemon=True)
        self.thread.start()

    def _read(self, pipe):
        half = KEEP // 2
        try:
            while chunk := pipe.read1(1 << 16):
                self.hash.update(chunk)
                self.total += len(chunk)
                room = half - len(self.head)
                if room > 0:
                    self.head += chunk[:room]
                    chunk = chunk[room:]
                self.tail += chunk
                del self.tail[:-half]
        except (OSError, ValueError):  # pipe closed under us
            pass

    def result(self):
        self.thread.join(DRAIN_S)  # a process that left a child holding the pipe does not block us
        return captured(self.head, self.tail, self.total, self.hash.hexdigest())


def run_cmd(argv, timeout=None):
    """Run a command with msb_env(). stdout and stderr come back as Captured text, so a step that
    floods its output cannot fill the control plane's memory."""
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=msb_env()) as p:
        out, err = _Drain(p.stdout), _Drain(p.stderr)
        try:
            rc = p.wait(timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            raise subprocess.TimeoutExpired(argv, timeout, output=out.result(), stderr=err.result()) from None
        return subprocess.CompletedProcess(argv, rc, out.result(), err.result())


def _as_captured(data):
    if isinstance(data, Captured):
        return data
    return captured(data if isinstance(data, bytes) else (data or "").encode())


GUEST_PATH = re.compile(r"(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)+")  # no "." or ".." segments
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
GUEST_USER = re.compile(r"[0-9]{1,5}:[0-9]{1,5}")  # numeric uid:gid, so the guest's /etc/passwd does not matter


@dataclass
class Exec:
    argv: list
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


class Session:
    """A microVM that lives for several actions: copy files in, run commands, start servers in the
    background, copy one built file out. Same limits, label, network policy and cleanup as
    Runner.run_step, and the same rule: every command must be in the approved allowlist.

        with runner.session(allow, "job1", "build", image) as s:
            s.copy_in(snapshot_dir, "/work/src")
            s.exec(["make", "test"], workdir="/work/src")
    """

    def __init__(self, runner, allow, job, step, image, limits=Limits()):
        for part in (job, step):
            if not NAME_PART.match(part):
                raise ValueError(f"job and step must match {NAME_PART.pattern}: {part!r}")
        if not allow.allows_image(image):
            raise SandboxError(f"image is not in the approved allowlist: {image!r}")
        self.runner, self.allow, self.image, self.limits = runner, allow, image, limits
        self.started_at = runner._clock()
        self.name = f"pq-{int(self.started_at)}-{job}-{step}-{secrets.token_hex(4)}"
        self.host_commands, self.execs, self.destroyed_at = [], [], None

    def __enter__(self):
        lim = self.limits
        try:
            r = self.runner._msb(self.host_commands, "create", "-q", "--name", self.name,
                                 "--cpus", str(lim.cpus), "--memory", f"{lim.memory_mib}M",
                                 "--max-duration", f"{lim.wall_clock_s}s", "--label", LABEL,
                                 "--pull", "never", *self.runner.net_args(), "--", self.image)
            if r.returncode != 0:
                raise SandboxError(f"msb create failed: {r.stderr.strip()[-300:]}")
        except BaseException:
            self._destroy()
            raise
        return self

    def __exit__(self, *exc):
        self._destroy()

    def _destroy(self):
        r = self.runner._msb(self.host_commands, "rm", "--force", "-q", self.name)
        if r.returncode == 0 or not self.runner._exists(self.name):
            self.destroyed_at = self.runner._clock()

    def remaining(self):
        return max(1.0, self.started_at + self.limits.wall_clock_s - self.runner._clock())

    def _check(self, argv, env, workdir, user=None):
        if not self.allow.allows_command(argv):
            raise SandboxError(f"command is not in the approved allowlist: {list(argv)!r}")
        opts = []
        if user is not None:
            if not isinstance(user, str) or not GUEST_USER.fullmatch(user):
                raise SandboxError(f"guest user must be numeric uid:gid: {user!r}")
            opts += ["-u", user]
        for k, v in (env or {}).items():
            if not ENV_NAME.fullmatch(k) or not re.fullmatch(r"[A-Za-z0-9_.,:/=-]*", v):
                raise SandboxError(f"environment entry not allowed: {k!r}")
            opts += ["-e", f"{k}={v}"]
        if workdir is not None:
            if not GUEST_PATH.fullmatch(workdir):
                raise SandboxError(f"workdir must be an absolute guest path: {workdir!r}")
            opts += ["-w", workdir]
        return opts

    def exec(self, argv, env=None, workdir=None, user=None):
        """Run argv to completion inside the microVM (as root, or as user "uid:gid").
        Returns Exec (also kept in self.execs)."""
        opts = self._check(argv, env, workdir, user)
        try:
            r = self.runner._msb(self.host_commands, "exec", "--no-stdin", *opts, self.name, "--", *argv,
                                 timeout=self.remaining() + GRACE_S)
            res = Exec(list(argv), r.returncode, _as_captured(r.stdout), _as_captured(r.stderr))
        except subprocess.TimeoutExpired as e:
            res = Exec(list(argv), None, _as_captured(e.stdout), _as_captured(e.stderr), timed_out=True)
        self.execs.append(res)
        return res

    def start(self, argv, env=None, workdir=None, user=None):
        """Start argv as a background job inside the microVM (msb exec -d), as root or as user
        "uid:gid". Returns the job id. The job ends with the microVM."""
        opts = self._check(argv, env, workdir, user)
        r = self.runner._msb(self.host_commands, "exec", "-d", *opts, self.name, "--", *argv)
        if r.returncode != 0:
            raise SandboxError(f"msb exec -d failed: {r.stderr.strip()[-300:]}")
        return str(r.stdout).strip()

    def logs(self, job, tail=50):
        """The last `tail` lines a background job (from start) printed, stdout and stderr; it is
        the guest's text, so it is treated like any step output. '' when msb cannot read it."""
        r = self.runner._msb(self.host_commands, "logs", "--job", str(job), "--tail", str(int(tail)), self.name)
        return str(_as_captured(r.stdout)) + str(_as_captured(r.stderr)) if r.returncode == 0 else ""

    def copy_in(self, src, dest):
        """Copy a host file or directory to an absolute guest path. Symlinks are copied as links."""
        if not GUEST_PATH.fullmatch(dest):
            raise SandboxError(f"guest path must be absolute: {dest!r}")
        if not os.path.lexists(src):
            raise SandboxError(f"nothing to copy at {src!r}")
        r = self.runner._msb(self.host_commands, "copy", "-q", os.fspath(src), f"{self.name}:{dest}")
        if r.returncode != 0:
            raise SandboxError(f"msb copy in failed: {r.stderr.strip()[-300:]}")

    def copy_out(self, src, dest_dir):
        """Copy one guest file into dest_dir and return its host path. The guest is untrusted, so
        anything that does not land as a regular file (a symlink, a directory) is removed and refused."""
        if not GUEST_PATH.fullmatch(src):
            raise SandboxError(f"guest path must be absolute: {src!r}")
        dest = os.path.join(dest_dir, posixpath_basename(src))
        if os.path.lexists(dest):
            raise SandboxError(f"refusing to overwrite {dest!r}")
        r = self.runner._msb(self.host_commands, "copy", "-q", f"{self.name}:{src}", dest)
        if r.returncode != 0:
            raise SandboxError(f"msb copy out failed: {r.stderr.strip()[-300:]}")
        try:
            st = os.lstat(dest)
        except FileNotFoundError:
            raise SandboxError(f"msb copy out produced nothing at {dest!r}") from None
        if not stat.S_ISREG(st.st_mode):
            if stat.S_ISDIR(st.st_mode) and not os.path.islink(dest):
                shutil.rmtree(dest)
            else:
                os.unlink(dest)
            raise SandboxError(f"{src} is not a regular file in the guest")
        return dest


def posixpath_basename(path):
    return path.rstrip("/").rsplit("/", 1)[-1]


class Runner:
    def __init__(self, msb=MSB, run=run_cmd, clock=time.time, egress=None):
        self.msb, self._run, self._clock, self.egress = msb, run, clock, egress

    def net_args(self):
        """Network policy for every step: the sinkhole's (egress.Sinkhole), or deny everything."""
        return self.egress.msb_args() if self.egress else ["--no-net"]

    def _msb(self, log, *args, timeout=60):
        argv = [self.msb, *args]
        log.append(argv)
        return self._run(argv, timeout=timeout)

    def run_step(self, allow, job, step, image, argv, limits=Limits()):
        """Create a microVM from `image`, run argv in it, destroy it. Returns a StepResult.

        `allow` is the approved plan.Allowlist; anything it does not hold is refused before msb runs.
        """
        for part in (job, step):
            if not NAME_PART.match(part):
                raise ValueError(f"job and step must match {NAME_PART.pattern}: {part!r}")
        if not allow.allows_image(image):
            raise SandboxError(f"image is not in the approved allowlist: {image!r}")
        if not allow.allows_command(argv):
            raise SandboxError(f"command is not in the approved allowlist: {list(argv)!r}")
        started = self._clock()
        # A random suffix keeps two runs of the same step in the same second apart, so the
        # `rm --force` below can only ever remove this step's own sandbox.
        name = f"pq-{int(started)}-{job}-{step}-{secrets.token_hex(4)}"
        res = StepResult(name=name, image=image, argv=list(argv), limits=limits, started_at=started)
        try:
            r = self._msb(res.host_commands, "create", "-q", "--name", name,
                          "--cpus", str(limits.cpus), "--memory", f"{limits.memory_mib}M",
                          "--max-duration", f"{limits.wall_clock_s}s", "--label", LABEL,
                          "--pull", "never", *self.net_args(), "--", image)
            if r.returncode != 0:
                raise SandboxError(f"msb create failed: {r.stderr.strip()[-300:]}")
            remaining = max(1.0, started + limits.wall_clock_s - self._clock())
            try:
                r = self._msb(res.host_commands, "exec", "--no-stdin", name, "--", *argv,
                              timeout=remaining + GRACE_S)
                res.exit_code, res.stdout, res.stderr = r.returncode, _as_captured(r.stdout), _as_captured(r.stderr)
            except subprocess.TimeoutExpired as e:
                res.stdout, res.stderr = _as_captured(e.stdout), _as_captured(e.stderr)
            res.timed_out = self._clock() - started >= limits.wall_clock_s
        finally:
            r = self._msb(res.host_commands, "rm", "--force", "-q", name)
            if r.returncode == 0 or not self._exists(name):  # the reaper may have removed it first
                res.destroyed_at = self._clock()
        return res

    def session(self, allow, job, step, image, limits=Limits()):
        """One microVM for several actions: Session (use it as a context manager)."""
        return Session(self, allow, job, step, image, limits)

    def _exists(self, name):
        try:
            return name in {s["name"] for s in self.list()}
        except (SandboxError, OSError, ValueError, subprocess.TimeoutExpired):
            return True  # unknown: do not claim it was destroyed

    def list(self):
        """pqproof sandboxes: [{name, status, created_at, image}]."""
        r = self._run([self.msb, "ls", "--label", LABEL, "--format", "json"], timeout=60)
        if r.returncode != 0:
            raise SandboxError(f"msb ls failed: {r.stderr.strip()[-300:]}")
        return json.loads(r.stdout or "[]")

    def reap(self, max_age_s):
        """Remove pqproof sandboxes older than max_age_s, or already stopped. Returns their names.

        Each removal is logged with its msb command line. An entry that cannot be read is logged
        and skipped without stopping the rest.
        """
        now, reaped = self._clock(), []
        for sb in self.list():
            try:
                stopped = str(sb.get("status", "")).lower() in ("stopped", "crashed")
                if stopped or now - datetime.datetime.fromisoformat(sb["created_at"]).timestamp() > max_age_s:
                    argv = [self.msb, "rm", "--force", "-q", sb["name"]]
                    if self._run(argv, timeout=60).returncode == 0:
                        log.info("reaped: %s", " ".join(argv))
                        reaped.append(sb["name"])
            except Exception as e:  # noqa: BLE001 - one odd entry must not stop the reaper
                log.warning("reaper skipped an entry: %s: %s", type(e).__name__, e)
        return reaped

    def start_reaper(self, max_age_s=MAX_WALL_CLOCK_S + REAP_GRACE_S, interval_s=60):
        """Reap now and then every interval_s in a daemon thread. Set the returned Event to stop."""
        stop = threading.Event()

        def loop():
            while True:
                try:
                    self.reap(max_age_s)
                except Exception as e:  # noqa: BLE001 - a dead reaper thread would leave VMs behind
                    log.warning("reaper: %s: %s (retrying next tick)", type(e).__name__, e)
                if stop.wait(interval_s):
                    return

        threading.Thread(target=loop, name="pqproof-reaper", daemon=True).start()
        return stop
