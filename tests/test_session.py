"""Runner.session: one microVM for several actions, with the same allowlist rule and cleanup."""
import json
import os
import pathlib
import resource
import subprocess
import sys
import tempfile
import unittest

from helpers import allow, msb_available
from pqproof.images import NGINX_BOOKWORM
from pqproof.sandbox import COPY_OUT_MAX, LABEL, Runner, SandboxError, run_cmd

IMG = "golang:1.27-bookworm@sha256:" + "1" * 64


class FakeMsb:
    """Records calls. copy out writes `out_kind` (file, symlink, dir or nothing) at the host path."""

    def __init__(self, out_kind="file", exec_rc=0, create_rc=0):
        self.out_kind, self.exec_rc, self.create_rc, self.calls, self.boxes = out_kind, exec_rc, create_rc, [], set()

    def __call__(self, argv, timeout=None, max_file_bytes=None):
        self.calls.append(argv)
        cmd = argv[1]
        if cmd == "create":
            if self.create_rc:
                return subprocess.CompletedProcess(argv, 1, "", "boot failed")
            self.boxes.add(argv[argv.index("--name") + 1])
        elif cmd == "copy" and ":" in argv[3]:  # guest -> host
            dest = argv[4]
            if self.out_kind == "file":
                pathlib.Path(dest).write_bytes(b"\x7fELF")
            elif self.out_kind == "symlink":
                os.symlink("/etc/passwd", dest)
            elif self.out_kind == "dir":
                os.mkdir(dest)
        elif cmd == "exec":
            if "-d" in argv:
                return subprocess.CompletedProcess(argv, 0, "job_1\n", "")
            return subprocess.CompletedProcess(argv, self.exec_rc, "out\n", "err\n")
        elif cmd == "rm":
            self.boxes.discard(argv[-1])
        elif cmd == "ls":
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"name": n} for n in self.boxes]), "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.allow = allow(IMG, ["make", "test"], ["go", "build", "-o=out/api", "./cmd/api"])

    def test_create_copy_exec_start_copy_out_rm(self):
        msb = FakeMsb()
        with Runner(msb="msb", run=msb).session(self.allow, "job1", "build", IMG) as s:
            s.copy_in(self.tmp.name, "/work/src")
            r = s.exec(["make", "test"], env={"GOFLAGS": "-mod=vendor"}, workdir="/work/src")
            job = s.start(["go", "build", "-o=out/api", "./cmd/api"])
            out = s.copy_out("/work/src/out/api", self.tmp.name)
        self.assertEqual((r.exit_code, str(r.stdout), job), (0, "out\n", "job_1"))
        self.assertEqual(pathlib.Path(out).read_bytes(), b"\x7fELF")
        n = s.name
        self.assertEqual([c[1] for c in s.host_commands], ["create", "copy", "exec", "exec", "copy", "rm"])
        self.assertIn(LABEL, s.host_commands[0])
        self.assertEqual(s.host_commands[0][-2:], ["--", IMG])
        self.assertEqual(s.host_commands[1], ["msb", "copy", "-q", self.tmp.name, f"{n}:/work/src"])
        self.assertEqual(s.host_commands[2], ["msb", "exec", "--no-stdin", "-e", "GOFLAGS=-mod=vendor", "-w", "/work/src",
                                              n, "--", "make", "test"])
        self.assertEqual(s.host_commands[3][:4], ["msb", "exec", "-d", n])
        self.assertEqual(s.host_commands[-1], ["msb", "rm", "--force", "-q", n])
        self.assertIsNotNone(s.destroyed_at)

    def test_a_background_job_s_output(self):
        # review day 2 (S1): when a server cannot bind its port, its own error goes back to the model
        msb = FakeMsb()
        with Runner(msb="msb", run=msb).session(self.allow, "job1", "prove", IMG) as s:
            job = s.start(["make", "test"])
            self.assertEqual(s.logs(job, tail=50), "")  # FakeMsb prints nothing for logs
        self.assertIn(["msb", "logs", "--job", "job_1", "--tail", "50", s.name], s.host_commands)

    def test_run_as_a_guest_user(self):
        msb = FakeMsb()
        with Runner(msb="msb", run=msb).session(self.allow, "job1", "prove", IMG) as s:
            s.exec(["make", "test"], user="65534:65534")
            s.start(["make", "test"], user="65533:65533")
            for bad in ("root", "0", "65534", "1:2:3", "-1:0", "65534:65534 ", "--privileged"):
                with self.subTest(user=bad), self.assertRaises(SandboxError):
                    s.exec(["make", "test"], user=bad)
        execs = [c for c in msb.calls if c[1] == "exec"]
        self.assertEqual(execs[0][:6], ["msb", "exec", "--no-stdin", "-u", "65534:65534", s.name])
        self.assertEqual(execs[1][:5], ["msb", "exec", "-d", "-u", "65533:65533"])

    def test_refuses_what_the_allowlist_does_not_hold(self):
        msb = FakeMsb()
        with Runner(msb="msb", run=msb).session(self.allow, "j", "s", IMG) as s:
            for argv in (["make", "test", "X=1"], ["sh", "-c", "id"]):
                with self.assertRaises(SandboxError):
                    s.exec(argv)
                with self.assertRaises(SandboxError):
                    s.start(argv)
            with self.assertRaises(SandboxError):
                s.exec(["make", "test"], env={"GOFLAGS": "-mod=vendor; curl x"})
            with self.assertRaises(SandboxError):
                s.exec(["make", "test"], env={"lower": "x"})
            with self.assertRaises(SandboxError):
                s.exec(["make", "test"], workdir="relative")
        self.assertEqual([c[1] for c in s.host_commands], ["create", "rm"])
        with self.assertRaises(SandboxError):
            Runner(msb="msb", run=msb).session(self.allow, "j", "s", "alpine@sha256:" + "2" * 64)

    def test_copy_out_refuses_a_symlink_or_directory(self):
        for kind in ("symlink", "dir", "none"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as out:
                msb = FakeMsb(out_kind=kind)
                with Runner(msb="msb", run=msb).session(self.allow, "j", "s", IMG) as s:
                    with self.assertRaises(SandboxError):
                        s.copy_out("/work/src/out/api", out)
                self.assertEqual(os.listdir(out), [])  # nothing left on the host
                self.assertIsNotNone(s.destroyed_at)

    def test_copy_out_is_capped(self):
        # review day 2: a guest file of any size was written to the host (8-9 GiB free on the build Mac)
        class Big(FakeMsb):
            def __call__(self, argv, timeout=None, max_file_bytes=None):
                if argv[1] == "copy" and ":" in argv[3]:
                    self.cap = max_file_bytes
                    self.calls.append(argv)
                    with open(argv[4], "wb") as f:
                        f.truncate(2 << 30)  # sparse: no disk used
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return super().__call__(argv, timeout)
        msb = Big()
        with Runner(msb="msb", run=msb).session(self.allow, "job1", "build", IMG) as s:
            with self.assertRaises(SandboxError) as cm:
                s.copy_out("/work/src/out/api", self.tmp.name)
        self.assertIn("larger than", str(cm.exception))
        self.assertEqual(msb.cap, COPY_OUT_MAX)  # msb copy itself ran under the file size limit
        self.assertFalse(os.path.lexists(os.path.join(self.tmp.name, "api")))

    def test_copy_out_retries_msb_s_transient_read_session_error(self):
        # seen five times on msb 0.7.13 (day 2): copy out fails once, the same copy then works
        transient = "error: sandbox fs error: filesystem bulk transfer cancelled: unknown filesystem read session: 33554433"

        class Flaky(FakeMsb):
            def __init__(self, failures, stderr=transient):
                super().__init__()
                self.failures, self.stderr = failures, stderr

            def __call__(self, argv, timeout=None, max_file_bytes=None):
                if argv[1] == "copy" and ":" in argv[3] and self.failures:
                    self.failures -= 1
                    self.calls.append(argv)
                    return subprocess.CompletedProcess(argv, 1, "", self.stderr)
                return super().__call__(argv, timeout)

        for failures, ok in ((1, True), (2, True), (3, False)):
            msb = Flaky(failures)
            with self.subTest(failures=failures), tempfile.TemporaryDirectory() as d:
                with Runner(msb="msb", run=msb, sleep=lambda s: None).session(self.allow, "job1", "build", IMG) as s:
                    if ok:
                        self.assertEqual(pathlib.Path(s.copy_out("/work/src/out/api", d)).read_bytes(), b"\x7fELF")
                    else:
                        self.assertRaises(SandboxError, s.copy_out, "/work/src/out/api", d)
                self.assertEqual(sum(1 for c in s.host_commands if c[1] == "copy"), min(failures + 1, 3))
        msb = Flaky(1, stderr="error: no such file")  # anything else is not retried
        with tempfile.TemporaryDirectory() as d, Runner(msb="msb", run=msb).session(self.allow, "job1", "build", IMG) as s:
            self.assertRaises(SandboxError, s.copy_out, "/work/src/out/api", d)
        self.assertEqual(sum(1 for c in s.host_commands if c[1] == "copy"), 1)

    def test_run_cmd_file_size_limit(self):
        out = os.path.join(self.tmp.name, "big")
        code = f"open({out!r}, 'wb').write(b'x' * (3 << 20))"
        r = run_cmd([sys.executable, "-c", code], timeout=60, max_file_bytes=1 << 20)
        self.assertNotEqual(r.returncode, 0)
        self.assertLessEqual(os.path.getsize(out), 1 << 20)
        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        run_cmd([sys.executable, "-c", "pass"], timeout=60, max_file_bytes=1 << 20)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before)  # the control plane's own limit is back

    def test_copy_out_does_not_overwrite(self):
        pathlib.Path(self.tmp.name, "api").write_text("host file")
        with Runner(msb="msb", run=FakeMsb()).session(self.allow, "j", "s", IMG) as s:
            with self.assertRaises(SandboxError):
                s.copy_out("/work/src/out/api", self.tmp.name)
        self.assertEqual(pathlib.Path(self.tmp.name, "api").read_text(), "host file")

    def test_guest_paths_must_be_absolute(self):
        with Runner(msb="msb", run=FakeMsb()).session(self.allow, "j", "s", IMG) as s:
            for bad in ("work/src", "/work/../etc", "/work/src x", "/", "/work/./src"):
                with self.assertRaises(SandboxError):
                    s.copy_in(self.tmp.name, bad)
                with self.assertRaises(SandboxError):
                    s.copy_out(bad, self.tmp.name)

    def test_create_failure_still_removes(self):
        msb = FakeMsb(create_rc=1)
        s = Runner(msb="msb", run=msb).session(self.allow, "j", "s", IMG)
        with self.assertRaises(SandboxError):
            with s:
                self.fail("body must not run")
        self.assertEqual([c[1] for c in s.host_commands], ["create", "rm"])

    def test_exception_in_body_still_removes(self):
        msb = FakeMsb()
        with self.assertRaises(KeyError):
            with Runner(msb="msb", run=msb).session(self.allow, "j", "s", IMG) as s:
                raise KeyError("boom")
        self.assertEqual(s.host_commands[-1][1], "rm")
        self.assertEqual(msb.boxes, set())


@unittest.skipUnless(msb_available(), "msb not installed")
class RealCopyOut(unittest.TestCase):
    def test_a_file_over_the_cap_stops_msb_copy(self):
        img, mk = NGINX_BOOKWORM.ref, ["sh", "-c", "head -c 4194304 /dev/zero > /tmp/big"]  # test-only command
        with tempfile.TemporaryDirectory() as d, Runner().session(allow(img, mk), "itest", "copycap", img) as s:
            self.assertEqual(s.exec(mk).exit_code, 0)
            with self.assertRaises(SandboxError):
                s.copy_out("/tmp/big", d, max_bytes=1 << 20)
            self.assertEqual(os.listdir(d), [])  # nothing left behind
            self.assertEqual(os.path.getsize(s.copy_out("/tmp/big", d)), 4 << 20)  # under the default cap


if __name__ == "__main__":
    unittest.main()
