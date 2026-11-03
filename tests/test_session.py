"""Runner.session: one microVM for several actions, with the same allowlist rule and cleanup."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from helpers import allow
from pqproof.sandbox import LABEL, Runner, SandboxError

IMG = "golang:1.27-bookworm@sha256:" + "1" * 64


class FakeMsb:
    """Records calls. copy out writes `out_kind` (file, symlink, dir or nothing) at the host path."""

    def __init__(self, out_kind="file", exec_rc=0, create_rc=0):
        self.out_kind, self.exec_rc, self.create_rc, self.calls, self.boxes = out_kind, exec_rc, create_rc, [], set()

    def __call__(self, argv, timeout=None):
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


if __name__ == "__main__":
    unittest.main()
