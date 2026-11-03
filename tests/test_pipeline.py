"""pipeline: where TLS files go, which images build and run, and the host-build audit.
The whole pipeline runs for real in e2e/orders_edge.py; set PQPROOF_E2E_REPO to an orders-edge
checkout to run it from here (about 75 s on an M-series Mac, needs the pinned images cached)."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from pqproof.pipeline import PipelineError, guest_commands, host_build_count, stage_images, tls_layout
from pqproof.plan import Allowlist

ROOT = pathlib.Path(__file__).resolve().parent.parent
F1 = ROOT / "tests" / "fixtures" / "f1"
GO = "golang:1.27-bookworm@sha256:" + "1" * 64
NG = "nginx:1.30-trixie@sha256:" + "2" * 64


def images(*refs):
    return Allowlist(commands=frozenset(), paths=frozenset(), images=frozenset(refs))


class Layout(unittest.TestCase):
    def test_f1(self):
        lay = tls_layout(F1)
        self.assertEqual((lay.tls_dir, lay.servername), ("/etc/orders-edge/tls", "orders-edge.local"))
        self.assertEqual(lay.hosts, "localhost,127.0.0.1,orders-edge.local,orders-api.internal")

    def test_needs_one_directory_with_the_probe_file_names(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "nginx")
            p.mkdir()
            for conf in ("ssl_certificate /a/cert.pem;\nssl_certificate_key /b/key.pem;\n",
                         "ssl_certificate /a/server.crt;\nssl_certificate_key /a/server.key;\n",
                         "ssl_certificate cert.pem;\nssl_certificate_key key.pem;\n"):
                (p / "nginx.conf").write_text(conf)
                with self.subTest(conf=conf), self.assertRaises(PipelineError):
                    tls_layout(d)

    def test_symlinked_config_is_not_read(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            pathlib.Path(outside, "nginx.conf").write_text((F1 / "nginx" / "nginx.conf").read_text())
            pathlib.Path(d, "nginx").mkdir()
            os.symlink(pathlib.Path(outside, "nginx.conf"), pathlib.Path(d, "nginx", "nginx.conf"))
            with self.assertRaises(PipelineError):
                tls_layout(d)


class Stages(unittest.TestCase):
    def snap(self, dockerfile):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        pathlib.Path(d.name, "Dockerfile").write_text(dockerfile)
        return d.name

    def test_first_and_last_from_through_the_approved_pins(self):
        root = self.snap("FROM golang:1.27-bookworm AS build\nRUN x\nFROM nginx:1.30-trixie\n")
        pins = {"golang:1.27-bookworm": GO, "nginx:1.30-trixie": NG}
        self.assertEqual(stage_images(root, images(GO, NG), pins), (GO, NG))

    def test_unapproved_image_is_refused(self):
        root = self.snap("FROM golang:1.27-bookworm AS build\nFROM nginx:1.28-bookworm\n")
        with self.assertRaises(PipelineError) as cm:
            stage_images(root, images(GO, NG), {"golang:1.27-bookworm": GO})
        self.assertIn("line 2: FROM nginx:1.28-bookworm is not an approved image", str(cm.exception))
        # a pin that maps to something the approver did not see is refused too
        with self.assertRaises(PipelineError):
            stage_images(root, images(GO), {"golang:1.27-bookworm": GO, "nginx:1.28-bookworm": NG})

    def test_digest_in_the_dockerfile_must_be_approved_as_is(self):
        root = self.snap(f"FROM {GO}\n")
        self.assertEqual(stage_images(root, images(GO), {}), (GO, GO))
        with self.assertRaises(PipelineError):
            stage_images(root, images(NG), {})

    def test_missing_or_symlinked_dockerfile(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PipelineError):
                stage_images(d, images(GO), {})
            os.symlink("/etc/hosts", os.path.join(d, "Dockerfile"))
            with self.assertRaises(PipelineError):
                stage_images(d, images(GO), {})


class Audit(unittest.TestCase):
    def test_host_build_count(self):
        host = [["git", "clone", "-q", "x", "y"], ["msb", "exec", "--no-stdin", "n", "--", "make", "test"],
                ["msb", "exec", "--no-stdin", "-w", "/work/src", "n", "--", "go", "build", "./..."],
                ["/Users/x/.local/bin/msb", "exec", "-d", "n", "--", "nginx", "-c", "/a"]]
        self.assertEqual(host_build_count(host), 0)
        self.assertEqual(host_build_count(host + [["go", "build", "./..."], ["/usr/bin/make", "test"]]), 2)
        self.assertEqual(guest_commands(host), [["make", "test"], ["go", "build", "./..."], ["nginx", "-c", "/a"]])


@unittest.skipUnless(os.environ.get("PQPROOF_E2E_REPO"), "set PQPROOF_E2E_REPO to an orders-edge checkout")
class EndToEnd(unittest.TestCase):
    def test_orders_edge(self):
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-I", str(ROOT / "e2e" / "orders_edge.py"), "--repo",
                                os.environ["PQPROOF_E2E_REPO"], "--out", os.path.join(out, "run"), "--approve"],
                               capture_output=True, text=True, timeout=900)
            self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
            report = json.loads(pathlib.Path(out, "run", "report.json").read_text())
        self.assertTrue(report["passed"])
        self.assertEqual(report["checks"]["host_build_commands"], 0)


if __name__ == "__main__":
    unittest.main()
