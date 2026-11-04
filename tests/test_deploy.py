"""deploy/: the VX1 host setup script and the upload script.

upload.sh runs for real against a local "host": PQPROOF_SSH and PQPROOF_SCP point at stand-ins
that run the remote command here, and PQPROOF_OPT / PQPROOF_ETC point into a temp directory.
"""
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
UPLOAD, SETUP = ROOT / "deploy" / "upload.sh", ROOT / "deploy" / "vx1-setup.sh"

FAKE_SSH = """#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -i|-o) shift 2 ;; -*) shift ;; *) break ;; esac; done
shift
exec sh -c "$1"
"""
FAKE_SCP = """#!/bin/sh
while [ $# -gt 2 ]; do shift; done
exec cp "$1" "${2#*:}"
"""


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Scripts(unittest.TestCase):
    def test_bash_syntax(self):
        for script in (UPLOAD, SETUP):
            subprocess.run(["bash", "-n", str(script)], check=True)
            self.assertTrue(os.access(script, os.X_OK), script)
            self.assertIn("set -euo pipefail", script.read_text())

    def test_setup_pins_the_installer_and_the_version(self):
        text = SETUP.read_text()
        self.assertRegex(text, r"\nMSB_INSTALL_SHA256=[0-9a-f]{64}\n")
        self.assertRegex(text, r"\nMSB_VERSION=\d+\.\d+\.\d+\n")
        # the installer runs only after the hash check, and never piped straight from curl
        self.assertLess(text.index('[ "$got" = "$MSB_INSTALL_SHA256" ]'), text.index('sh "$1"'))
        self.assertNotRegex(text, r"curl[^\n]*\|\s*(ba)?sh")
        self.assertIn('[ -s /root/.ssh/authorized_keys ] || die', text)
        self.assertLess(text.index("authorized_keys ] || die"), text.index("PasswordAuthentication no"))


@unittest.skipUnless((ROOT / ".git").exists(), "upload.sh sends a git HEAD: needs a git checkout of pq-proof")
class Upload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.opt, self.etc = t / "bin", t / "opt", t / "etc" / "pqproof"
        self.bin.mkdir()
        for name, body in (("ssh", FAKE_SSH), ("scp", FAKE_SCP)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        # a stand-in for the fixture: two commits, a file .gitignore would hide, an executable
        self.fixture = t / "orders-edge"
        self.fixture.mkdir()
        git("init", "-q", cwd=self.fixture)
        (self.fixture / "a.txt").write_text("one\n")
        (self.fixture / ".gitignore").write_text("*.pem\n")
        (self.fixture / "run.sh").write_text("#!/bin/sh\n")
        (self.fixture / "run.sh").chmod(0o755)
        (self.fixture / "ca.pem").write_text("not a secret\n")
        git("add", "-A", "-f", cwd=self.fixture)
        git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "1", cwd=self.fixture)
        (self.fixture / "a.txt").write_text("two\n")
        git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "2", cwd=self.fixture)
        git("remote", "add", "origin", "https://deploy:not-a-token-789@github.com/g1mn/orders-edge.git", cwd=self.fixture)
        self.key = t / "inference.env"
        self.key.write_text("# comment\nVULTR_INFERENCE_API_KEY=not-a-real-key-value-123\nnot-a-pair-secret-456\n")
        self.key.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, *args):
        me = f"{os.getuid()}:{os.getgid()}"
        env = {**os.environ, "PQPROOF_SSH": str(self.bin / "ssh"), "PQPROOF_SCP": str(self.bin / "scp"),
               "PQPROOF_OPT": str(self.opt), "PQPROOF_ETC": str(self.etc), "PQPROOF_KEY_OWNER": me,
               "PQPROOF_FIXTURE_OWNER": me}
        return subprocess.run(["bash", str(UPLOAD), *args, "root@host.invalid"], env=env,
                              capture_output=True, text=True, timeout=120)

    def test_upload_fixture_and_key(self):
        r = self.upload("--fixture", str(self.fixture), "--key", str(self.key))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rev = git("rev-parse", "--short=12", "HEAD", cwd=self.fixture)
        dest = self.opt / "orders-edge" / rev
        self.assertEqual(os.readlink(self.opt / "orders-edge" / "current"), rev)
        self.assertEqual((dest / "a.txt").read_text(), "two\n")
        self.assertTrue(os.access(dest / "run.sh", os.X_OK))
        self.assertEqual(stat.S_IMODE((dest / "a.txt").stat().st_mode), 0o644)  # tar.umask 0022
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o755)
        # the host copy is a git repo at the very commit of the source (day-3 review: a receipt named a
        # host-only snapshot commit no reader could find), ignored files included, and its origin is
        # the source's origin as https without credentials: what a receipt names as the repository
        self.assertEqual(git("rev-parse", "HEAD", cwd=dest), git("rev-parse", "HEAD", cwd=self.fixture))
        self.assertEqual(git("rev-parse", "HEAD^{tree}", cwd=dest), git("rev-parse", "HEAD^{tree}", cwd=self.fixture))
        self.assertEqual(git("status", "--porcelain", cwd=dest), "")
        self.assertEqual(git("remote", "get-url", "origin", cwd=dest), "https://github.com/g1mn/orders-edge")
        self.assertNotIn("not-a-token-789", (dest / ".git" / "config").read_text() + r.stdout + r.stderr)
        self.assertIn("tree", r.stdout)
        # pq-proof itself went over as its HEAD, with no .git
        own = git("rev-parse", "--short=12", "HEAD", cwd=ROOT)
        self.assertTrue((self.opt / "pq-proof" / own / "LICENSE").is_file())
        self.assertFalse((self.opt / "pq-proof" / own / ".git").exists())
        # the key: copied, mode 600 in a 700 directory, value never printed
        copied = self.etc / "inference.env"
        self.assertEqual(copied.read_text(), self.key.read_text())
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.etc.stat().st_mode), 0o700)
        self.assertIn("variables: VULTR_INFERENCE_API_KEY", r.stdout)
        for secret in ("not-a-real-key-value-123", "not-a-pair-secret-456"):
            self.assertNotIn(secret, r.stdout + r.stderr)

    def test_second_upload_sends_nothing(self):
        self.assertEqual(self.upload("--fixture", str(self.fixture)).returncode, 0)
        r = self.upload("--fixture", str(self.fixture))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(re.findall(r": already on the host", r.stdout)), 2, r.stdout)
        self.assertEqual([p.name for p in (self.opt / "orders-edge").iterdir() if p.name.startswith(".part")], [])

    def test_a_host_snapshot_commit_is_replaced_by_the_source_commit(self):
        # what upload.sh made before: a fresh repository with one local commit of the same tree
        self.assertEqual(self.upload("--fixture", str(self.fixture)).returncode, 0)
        dest = self.opt / "orders-edge" / git("rev-parse", "--short=12", "HEAD", cwd=self.fixture)
        local = git("-c", "user.name=d", "-c", "user.email=d@localhost", "commit-tree", "HEAD^{tree}", "-m", "snapshot", cwd=dest)
        git("update-ref", "HEAD", local, cwd=dest)
        git("remote", "remove", "origin", cwd=dest)
        r = self.upload("--fixture", str(self.fixture))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(git("rev-parse", "HEAD", cwd=dest), git("rev-parse", "HEAD", cwd=self.fixture))
        self.assertEqual(git("remote", "get-url", "origin", cwd=dest), "https://github.com/g1mn/orders-edge")

    def test_a_changed_host_tree_is_refused(self):
        self.assertEqual(self.upload("--fixture", str(self.fixture)).returncode, 0)
        rev = git("rev-parse", "--short=12", "HEAD", cwd=self.fixture)
        dest = self.opt / "orders-edge" / rev
        (dest / "a.txt").write_text("tampered\n")
        git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "x", cwd=dest)
        r = self.upload("--fixture", str(self.fixture))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("tree mismatch", r.stderr)


if __name__ == "__main__":
    unittest.main()
