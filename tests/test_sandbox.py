"""Sandbox runner: limits, wall clock, cleanup and the reaper.

Unit tests use a fake msb. Integration tests run the real `msb` when it is installed
(skip with PQPROOF_MSB_TESTS=0). PQPROOF_WALL_S sets the integration wall clock
(default 5 s; run once with 120 to check the real limit).
"""
import datetime
import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
import unittest

from helpers import allow, msb_available, pinned
from pqproof.sandbox import LABEL, MSB, Limits, Runner, SandboxError

ROOT = pathlib.Path(__file__).resolve().parent.parent
T0 = 1_793_718_000.0  # 2026-11-03T16:20:00Z
IMG = "alpine@sha256:" + "0" * 64


def done(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeMsb:
    def __init__(self, clock, exec_result=None, create_rc=0):
        self.clock, self.exec_result, self.create_rc = clock, exec_result, create_rc
        self.boxes, self.calls = {}, []

    def __call__(self, argv, timeout=None):
        self.calls.append((argv, timeout))
        cmd = argv[1]
        if cmd == "create":
            if self.create_rc:
                return done(argv, self.create_rc, err="boot failed")
            name = argv[argv.index("--name") + 1]
            self.boxes[name] = {"name": name, "image": argv[-1], "status": "Running",
                                "created_at": datetime.datetime.fromtimestamp(self.clock.now, datetime.UTC).isoformat()}
            return done(argv)
        if cmd == "exec":
            r = self.exec_result(argv, timeout) if callable(self.exec_result) else self.exec_result
            if isinstance(r, BaseException):
                raise r
            return r or done(argv, 0, "ok\n")
        if cmd == "rm":
            return done(argv, 0 if self.boxes.pop(argv[-1], None) else 1)
        if cmd == "ls":
            return done(argv, 0, json.dumps(list(self.boxes.values())))
        raise AssertionError(f"unexpected msb call {argv}")


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class RunStep(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()

    def step(self, msb, image=IMG, argv=("true",), limits=Limits(), job="j", step="s"):
        return Runner(msb="msb", run=msb, clock=self.clock).run_step(allow(image, argv), job, step, image,
                                                                      list(argv), limits)

    def test_limits_labels_and_cleanup(self):
        msb = FakeMsb(self.clock)
        go = f"golang:1.25-bookworm@sha256:{'1' * 64}"
        res = self.step(msb, go, ["make", "test"], job="job1", step="build")
        create, exec_, rm = res.host_commands
        self.assertRegex(res.name, rf"^pq-{int(T0)}-job1-build-[0-9a-f]{{8}}$")
        self.assertEqual(create, ["msb", "create", "-q", "--name", res.name, "--cpus", "1",
                                  "--memory", "1024M", "--max-duration", "120s", "--label", LABEL,
                                  "--pull", "never", "--no-net", "--", go])
        self.assertEqual(exec_, ["msb", "exec", "--no-stdin", res.name, "--", "make", "test"])
        self.assertEqual(rm, ["msb", "rm", "--force", "-q", res.name])
        self.assertEqual((res.exit_code, res.stdout, res.timed_out), (0, "ok\n", False))
        self.assertEqual(res.destroyed_at, T0)
        self.assertEqual(msb.boxes, {})

    def test_exec_timeout_is_the_remaining_wall_clock(self):
        msb = FakeMsb(self.clock)
        self.step(msb, limits=Limits(wall_clock_s=30))
        exec_timeout = [t for a, t in msb.calls if a[1] == "exec"][0]
        self.assertEqual(exec_timeout, 30 + 5)

    def test_wall_clock_kills_and_destroys(self):
        def hang(argv, timeout):
            self.clock.now += timeout  # the host timer fires
            return subprocess.TimeoutExpired(argv, timeout, output=b"partial", stderr=b"")
        msb = FakeMsb(self.clock, exec_result=hang)
        res = self.step(msb, argv=["sleep", "600"])
        self.assertTrue(res.timed_out)
        self.assertIsNone(res.exit_code)
        self.assertEqual(res.stdout, "partial")
        self.assertEqual(res.destroyed_at, T0 + 125)
        self.assertEqual(msb.boxes, {})

    def test_runtime_kill_counts_as_timeout(self):
        def killed(argv, timeout):  # msb --max-duration ended the VM first
            self.clock.now += 120
            return done(argv, 1, err="error: exec session ended without exit event")
        res = self.step(FakeMsb(self.clock, exec_result=killed), argv=["sleep", "600"])
        self.assertTrue(res.timed_out)
        self.assertEqual(res.exit_code, 1)

    def test_exception_during_exec_still_destroys(self):
        msb = FakeMsb(self.clock, exec_result=OSError("msb vanished"))
        with self.assertRaises(OSError):
            self.step(msb)
        self.assertEqual(msb.boxes, {})
        self.assertEqual(msb.calls[-1][0][1], "rm")

    def test_create_failure(self):
        msb = FakeMsb(self.clock, create_rc=1)
        with self.assertRaises(SandboxError):
            self.step(msb)
        self.assertNotIn("exec", [a[1] for a, _ in msb.calls])

    def test_names_are_checked(self):
        for bad in ("Job", "a b", "a/b", "", "x" * 50):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.step(FakeMsb(self.clock), job=bad)

    def test_same_step_in_the_same_second_gets_its_own_sandbox(self):
        # A retry loop or two requests: the second step's cleanup must not remove the first's VM.
        msb = FakeMsb(self.clock)
        names = {self.step(msb).name for _ in range(20)}
        self.assertEqual(len(names), 20)
        removed = [a[-1] for a, _ in msb.calls if a[1] == "rm"]
        self.assertEqual(sorted(removed), sorted(names))

    def test_runs_only_what_the_allowlist_holds(self):
        approved = allow(IMG, ["make", "test"])
        for image, argv in ((IMG, ["make", "test", "EXTRA=1"]), (IMG, ["sh", "-c", "id"]),
                            ("alpine@sha256:" + "f" * 64, ["make", "test"]), ("alpine", ["make", "test"])):
            msb = FakeMsb(self.clock)
            with self.subTest(image=image, argv=argv), self.assertRaises(SandboxError):
                Runner(run=msb, clock=self.clock).run_step(approved, "j", "s", image, argv)
            self.assertEqual(msb.calls, [], "no msb call before the allowlist check")

    def test_image_is_never_read_as_an_msb_option(self):
        image = "--conf=/tmp/attacker.yaml"  # even if an allowlist were built by hand around one
        msb = FakeMsb(self.clock)
        self.step(msb, image=image)
        create = msb.calls[0][0]
        self.assertEqual(create[-2:], ["--", image])


class Reaper(unittest.TestCase):
    def test_removes_old_and_stopped_keeps_young(self):
        clock = Clock()
        msb = FakeMsb(clock)
        iso = lambda ago: datetime.datetime.fromtimestamp(T0 - ago, datetime.UTC).isoformat()
        msb.boxes = {
            "pq-old": {"name": "pq-old", "status": "Running", "created_at": iso(600), "image": "alpine"},
            "pq-young": {"name": "pq-young", "status": "Running", "created_at": iso(10), "image": "alpine"},
            "pq-stopped": {"name": "pq-stopped", "status": "Stopped", "created_at": iso(10), "image": "alpine"},
        }
        reaped = Runner(run=msb, clock=clock).reap(max_age_s=150)
        self.assertEqual(sorted(reaped), ["pq-old", "pq-stopped"])
        self.assertEqual(list(msb.boxes), ["pq-young"])
        self.assertEqual(msb.calls[0][0], ["msb", "ls", "--label", LABEL, "--format", "json"])

    def test_loop_runs_at_start(self):
        clock = Clock()
        msb = FakeMsb(clock)
        msb.boxes = {"pq-x": {"name": "pq-x", "status": "Stopped", "image": "alpine",
                              "created_at": datetime.datetime.fromtimestamp(T0, datetime.UTC).isoformat()}}
        stop = Runner(run=msb, clock=clock).start_reaper(interval_s=3600)
        for _ in range(100):
            if not msb.boxes:
                break
            time.sleep(0.01)
        stop.set()
        self.assertEqual(msb.boxes, {})


@unittest.skipUnless(msb_available(), "msb not installed")
class RealMsb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.IMAGE = pinned("alpine")

    def step(self, name, argv, limits):
        return Runner().run_step(allow(self.IMAGE, argv), "itest", name, self.IMAGE, argv, limits)

    def names(self):
        return {s["name"] for s in Runner().list()}

    def test_sleep_600_is_cut_at_the_wall_clock(self):
        wall = int(os.environ.get("PQPROOF_WALL_S", "5"))
        t = time.monotonic()
        res = self.step("wall", ["sleep", "600"], Limits(cpus=1, memory_mib=256, wall_clock_s=wall))
        elapsed = time.monotonic() - t
        self.assertLess(elapsed, wall + 5)
        self.assertTrue(res.timed_out)
        self.assertIsNotNone(res.destroyed_at)
        self.assertNotIn(res.name, self.names())

    def test_limits_are_applied_inside_the_vm(self):
        res = self.step("limits", ["nproc"], Limits(cpus=1, memory_mib=256))
        self.assertEqual((res.exit_code, res.stdout.strip()), (0, "1"))

    def test_same_name_step_does_not_destroy_a_running_step(self):
        fixed = time.time()
        runner, out = Runner(clock=lambda: fixed), {}
        slow, fast = ["sh", "-c", "sleep 6; echo DONE"], ["true"]
        approved = allow(self.IMAGE, slow, fast)
        first = threading.Thread(target=lambda: out.setdefault("first", runner.run_step(
            approved, "itest", "dup", self.IMAGE, slow, Limits(memory_mib=256, wall_clock_s=30))))
        first.start()
        for _ in range(100):
            if any(n.startswith(f"pq-{int(fixed)}-itest-dup-") for n in self.names()):
                break
            time.sleep(0.1)
        second = runner.run_step(approved, "itest", "dup", self.IMAGE, fast, Limits(memory_mib=256, wall_clock_s=30))
        first.join(timeout=60)
        self.assertEqual(second.exit_code, 0)
        self.assertIn("DONE", out["first"].stdout, out["first"].stderr)
        self.assertNotEqual(out["first"].name, second.name)

    def test_reaper_removes_what_a_killed_control_plane_left(self):
        code = ("import sys; from helpers import allow; from pqproof.sandbox import Runner, Limits; "
                "img, argv = sys.argv[1], ['sleep', '600']; "
                "Runner().run_step(allow(img, argv), 'itest', 'orphan', img, argv, Limits(wall_clock_s=60))")
        env = {**os.environ, "PYTHONPATH": f"{ROOT}{os.pathsep}{ROOT / 'tests'}"}
        cp = subprocess.Popen([sys.executable, "-c", code, self.IMAGE], env=env, start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            orphan = None
            for _ in range(120):
                orphan = next((n for n in self.names() if "-itest-orphan-" in n), None)
                if orphan:
                    break
                time.sleep(0.25)
            self.assertIsNotNone(orphan, "control plane never created its sandbox")
            os.killpg(cp.pid, signal.SIGKILL)  # the control plane dies mid-step
            cp.wait(timeout=10)
            self.assertIn(orphan, self.names())  # left behind
            self.assertIn(orphan, Runner().reap(max_age_s=0))  # a restarted control plane reaps it
            self.assertNotIn(orphan, self.names())
        finally:
            if cp.poll() is None:
                os.killpg(cp.pid, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
