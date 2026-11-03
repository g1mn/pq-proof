"""Run each step in a fresh Microsandbox microVM through the `msb` CLI.

Three layers keep a step bounded and leave nothing behind:
1. `msb create --max-duration`: the runtime kills the microVM at the wall clock.
2. A host-side timeout on `msb exec`, then `msb rm --force` in a finally block.
3. A reaper loop that removes any pqproof-labelled sandbox past its lifetime, so a crashed
   control plane cannot leave microVMs running.
Every msb command line is kept in StepResult.host_commands for the receipt.
"""
import datetime
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field

MSB = os.environ.get("PQPROOF_MSB", "msb")
LABEL = "app=pqproof"
GRACE_S = 5
NAME_PART = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class Limits:
    cpus: int = 1
    memory_mib: int = 1024
    wall_clock_s: int = 120


@dataclass
class StepResult:
    name: str
    image: str
    argv: list
    limits: Limits
    started_at: float
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    destroyed_at: float | None = None
    host_commands: list = field(default_factory=list)


def run_cmd(argv, timeout=None):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def _text(data):
    return data.decode(errors="replace") if isinstance(data, bytes) else (data or "")


class Runner:
    def __init__(self, msb=MSB, run=run_cmd, clock=time.time):
        self.msb, self._run, self._clock = msb, run, clock

    def _msb(self, log, *args, timeout=60):
        argv = [self.msb, *args]
        log.append(argv)
        return self._run(argv, timeout=timeout)

    def run_step(self, job, step, image, argv, limits=Limits()):
        """Create a microVM, run argv in it, destroy it. Returns a StepResult."""
        for part in (job, step):
            if not NAME_PART.match(part):
                raise ValueError(f"job and step must match {NAME_PART.pattern}: {part!r}")
        started = self._clock()
        name = f"pq-{int(started)}-{job}-{step}"
        res = StepResult(name=name, image=image, argv=list(argv), limits=limits, started_at=started)
        try:
            r = self._msb(res.host_commands, "create", "-q", "--name", name,
                          "--cpus", str(limits.cpus), "--memory", f"{limits.memory_mib}M",
                          "--max-duration", f"{limits.wall_clock_s}s", "--label", LABEL,
                          "--pull", "never", image)
            if r.returncode != 0:
                raise SandboxError(f"msb create failed: {r.stderr.strip()[-300:]}")
            remaining = max(1.0, started + limits.wall_clock_s - self._clock())
            try:
                r = self._msb(res.host_commands, "exec", "--no-stdin", name, "--", *argv,
                              timeout=remaining + GRACE_S)
                res.exit_code, res.stdout, res.stderr = r.returncode, r.stdout, r.stderr
            except subprocess.TimeoutExpired as e:
                res.stdout, res.stderr = _text(e.stdout), _text(e.stderr)
            res.timed_out = self._clock() - started >= limits.wall_clock_s
        finally:
            r = self._msb(res.host_commands, "rm", "--force", "-q", name)
            if r.returncode == 0 or not self._exists(name):  # the reaper may have removed it first
                res.destroyed_at = self._clock()
        return res

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
        """Remove pqproof sandboxes older than max_age_s, or already stopped. Returns their names."""
        now, reaped = self._clock(), []
        for sb in self.list():
            age = now - datetime.datetime.fromisoformat(sb["created_at"]).timestamp()
            if age > max_age_s or sb.get("status", "").lower() in ("stopped", "crashed"):
                if self._run([self.msb, "rm", "--force", "-q", sb["name"]], timeout=60).returncode == 0:
                    reaped.append(sb["name"])
        return reaped

    def start_reaper(self, max_age_s=Limits().wall_clock_s + 30, interval_s=60):
        """Reap now and then every interval_s in a daemon thread. Set the returned Event to stop."""
        stop = threading.Event()

        def loop():
            while True:
                try:
                    self.reap(max_age_s)
                except (SandboxError, OSError, ValueError, subprocess.TimeoutExpired):
                    pass  # the next tick retries
                if stop.wait(interval_s):
                    return

        threading.Thread(target=loop, name="pqproof-reaper", daemon=True).start()
        return stop
