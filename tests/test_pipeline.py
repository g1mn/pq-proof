"""pipeline: where TLS files go, which images build and run, and the host-build audit.
The whole pipeline runs for real in e2e/orders_edge.py; set PQPROOF_E2E_REPO to an orders-edge
checkout to run it from here (about 75 s on an M-series Mac, needs the pinned images cached)."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from pqproof import prove
from helpers import msb_available
from pqproof import pipeline
from pqproof.images import GOLANG, NGINX_BOOKWORM, NGINX_TRIXIE
from pqproof.loop import apply_edits
from pqproof.pipeline import Layout as TlsLayout, Pipeline, PipelineError, guest_commands, host_build_count, stage_images, \
    tls_layout
from pqproof.sandbox import Runner
from pqproof.plan import Allowlist, compile_allowlist

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
        self.assertEqual(lay.pid, "/run/orders-edge-nginx.pid")

    def test_needs_an_absolute_pid_path(self):
        # nginx runs as an unprivileged user, so the control plane creates its pid file first
        conf = (F1 / "nginx" / "nginx.conf").read_text()
        for bad in (conf.replace("pid /run/orders-edge-nginx.pid;\n", ""),
                    conf.replace("pid /run/orders-edge-nginx.pid;", "pid nginx.pid;"),
                    conf.replace("pid /run/orders-edge-nginx.pid;", "pid /run/../etc/x;")):
            with tempfile.TemporaryDirectory() as d:
                pathlib.Path(d, "nginx").mkdir()
                pathlib.Path(d, "nginx", "nginx.conf").write_text(bad)
                with self.subTest(conf=bad[:80]), self.assertRaises(PipelineError):
                    tls_layout(d)

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


class FakeExec:
    def __init__(self, argv, out=""):
        self.argv, self.exit_code, self.stdout, self.stderr, self.timed_out = list(argv), 0, out, "", False


class FakeSession:
    """A prove or build microVM in which every server is classical-only (P-256) except the probe's
    own reference server. Commands must be in the session's allowlist, as with the real Session."""

    def __init__(self, runner, allow, step, image, limits):
        self.runner, self.allow, self.step, self.image, self.limits = runner, allow, step, image, limits
        self.name, self.started_at, self.destroyed_at = f"fake-{step}", 0.0, None
        self.host_commands, self.execs = [], []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.destroyed_at = 1.0

    def copy_in(self, src, dest):
        self.runner.log.append(("copy_in", dest))

    def copy_out(self, src, dest_dir):
        path = os.path.join(dest_dir, src.rsplit("/", 1)[-1])
        pathlib.Path(path).write_bytes(self.runner.probe_bytes if src == prove.GUEST_PROBE else b"built")
        return path

    def start(self, argv, **kw):
        assert self.allow.allows_command(argv), argv
        self.runner.log.append(("start", list(argv), kw))
        return "job"

    def exec(self, argv, **kw):
        assert self.allow.allows_command(argv), argv
        self.runner.log.append(("exec", list(argv), kw))
        out = ""
        if argv[:2] == ["tls_probe", "version"]:
            out = f"tls_probe {prove.PROBE_VERSION} (go1.27.3)\n"
        elif argv[:2] == ["tls_probe", "connect"]:
            out = self.runner.answer(argv)
        e = FakeExec(argv, out)
        self.execs.append(e)
        return e


class FakeRunner:
    def __init__(self, answer=None, probe_bytes=b""):
        self.log, self.probe_bytes = [], probe_bytes
        if answer:
            self.answer = answer

    def session(self, allow, job, step, image, limits=None):
        return FakeSession(self, allow, step, image, limits)

    hybrid_servers = False

    @staticmethod
    def answer(argv):
        target, offered = argv[-1], next(a for a in argv if a.startswith("-groups="))[8:].split(",")
        if target == prove.CONTROL_ADDR or (target != prove.NEGATIVE_ADDR and "X25519MLKEM768" in offered
                                            and FakeRunner.hybrid_servers):
            return "result: connected\nprotocol: TLS 1.3\ngroup: X25519MLKEM768\n"
        if "X25519" in offered:
            return "result: connected\nprotocol: TLS 1.3\ngroup: X25519\n"
        return "result: failed\nerror: remote error: tls: handshake failure\n"


PLAN = {"version": 1, "summary": "s", "edits": [{"path": "nginx/nginx.conf", "why": "w"}],
        "commands": [["make", "test"], ["go", "build", "-o=out/api", "./cmd/api"],
                     ["nginx", "-t", "-c", "/work/src/nginx/nginx.conf"], ["nginx", "-c", "/work/src/nginx/nginx.conf"],
                     ["api"]],
        "images": [GO, NG], "targets": ["127.0.0.1:8443", "127.0.0.1:9443"]}


def forged_probe(argv):
    """What the probe printed once review day 2's planted init() had replaced it with a shell script."""
    offered = next(a for a in argv if a.startswith("-groups="))[8:]
    return f"result: connected\nprotocol: TLS 1.3\ngroup: {'X25519MLKEM768' if 'MLKEM' in offered else 'X25519'}\n"


def fake_pipeline(test, allow, runner=None):
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    root = pathlib.Path(d.name, "snap")
    root.mkdir()
    (root / "Dockerfile").write_text("FROM golang:1.27-bookworm AS build\nFROM nginx:1.30-trixie\n")
    scratch = pathlib.Path(d.name, "scratch")
    scratch.mkdir()
    probe = prove.Probe("tls_probe", prove.PROBE_VERSION, hashlib.sha256(b"").hexdigest(), "0" * 64, GO, os.devnull)
    lay = TlsLayout("nginx/nginx.conf", "/etc/orders-edge/tls", "orders-edge.local", "localhost,127.0.0.1", "/run/x.pid")
    runner = runner or FakeRunner()
    pins = {"golang:1.27-bookworm": GO, "nginx:1.30-trixie": NG}
    return Pipeline(runner, allow, probe, lay, pins, "t", str(scratch)), str(root), runner


class Verdict(unittest.TestCase):
    """Review day 2 (fake microVMs): what the pipeline calls a pass."""

    def test_classical_only_servers_fail(self):
        pipe, root, _ = fake_pipeline(self, compile_allowlist(PLAN))
        res = pipe.build_and_prove(root, 0)
        self.assertFalse(res.ok)
        self.assertEqual(set(res.detail["verdict"]["targets"]), {"127.0.0.1:8443", "127.0.0.1:9443"})

    def test_no_target_is_not_a_pass(self):
        # an allowlist that skipped compile_allowlist: the pipeline itself must not pass on zero probes
        allow = compile_allowlist(PLAN)
        allow = Allowlist(commands=allow.commands, paths=allow.paths, images=allow.images)
        pipe, root, runner = fake_pipeline(self, allow)
        res = pipe.build_and_prove(root, 0)
        self.assertFalse(res.ok, res.detail.get("verdict"))
        self.assertIn("no target", res.raw_error)
        self.assertEqual(runner.log, [])  # nothing was built or started

    def test_a_probe_that_always_says_hybrid_is_caught(self):
        # review day 2 (S5): code in the prove microVM swapped tls_probe for a script that always
        # printed X25519MLKEM768; the positive control passed and so did every target.
        pipe, root, _ = fake_pipeline(self, compile_allowlist(PLAN), FakeRunner(forged_probe))
        res = pipe.build_and_prove(root, 0)
        self.assertFalse(res.ok, res.detail.get("verdict"))
        self.assertIn("negative control", res.raw_error)
        self.assertEqual(res.detail["verdict"]["targets"], {})  # no server verdict from a probe that lies
        self.assertIsNotNone(res.detail["prove"]["destroyed_at"])

    def test_negative_control_and_reference_servers_start_before_the_repo_s_servers(self):
        pipe, root, runner = fake_pipeline(self, compile_allowlist(PLAN))
        res = pipe.build_and_prove(root, 0)
        starts = [e[1] for e in runner.log if e[0] == "start"]
        serves = [a for a in starts if a[:2] == ["tls_probe", "serve"]]
        self.assertEqual([a[2] for a in serves], [f"-addr={prove.CONTROL_ADDR}", f"-addr={prove.NEGATIVE_ADDR}"])
        self.assertIn("-groups=X25519", serves[1])  # classical only
        self.assertEqual(starts[:2], serves)
        neg = res.detail["verdict"]["negative_control"]
        self.assertEqual((neg["hybrid"]["kind"], neg["classical"]["kind"], neg["classical"]["group"]),
                         ("failed", "classical", "X25519"))

    def test_the_repo_s_servers_run_unprivileged(self):
        # review day 2 (S5): the API ran as root and replaced /usr/local/bin/tls_probe
        pipe, root, runner = fake_pipeline(self, compile_allowlist(PLAN))
        pipe.build_and_prove(root, 0)
        starts = {e[1][0]: e[2].get("user") for e in runner.log if e[0] == "start" and e[1][0] != "tls_probe"}
        self.assertEqual(starts, {"api": pipeline.BUILT_USER, "nginx": pipeline.NGINX_USER})
        self.assertNotEqual(pipeline.BUILT_USER, pipeline.NGINX_USER)
        self.assertTrue(all(not u.startswith("0:") for u in starts.values()))
        nginx_t = [e for e in runner.log if e[0] == "exec" and e[1][:2] == ["nginx", "-t"]]
        self.assertEqual(nginx_t[0][2].get("user"), pipeline.NGINX_USER)
        # the control plane prepares the pid file and cache directory as root, before nginx -t
        execs = [e[1] for e in runner.log if e[0] == "exec"]
        prep = [a for a in execs if a[0] == "install"]
        self.assertEqual(len(prep), 2)
        self.assertLess(execs.index(prep[-1]), execs.index(nginx_t[0][1]))
        self.assertTrue(all(not e[2].get("user") for e in runner.log if e[0] == "exec" and e[1][0] in ("install", "tls_probe")))

    def test_a_changed_probe_binary_invalidates_the_proof(self):
        FakeRunner.hybrid_servers = True
        self.addCleanup(setattr, FakeRunner, "hybrid_servers", False)
        pipe, root, _ = fake_pipeline(self, compile_allowlist(PLAN), FakeRunner(probe_bytes=b"#!/bin/sh\n"))
        res = pipe.build_and_prove(root, 0)
        self.assertFalse(res.ok)
        self.assertIn("proof invalid", res.raw_error)
        self.assertIn("/usr/local/bin/tls_probe changed", res.raw_error)

    def test_hybrid_servers_pass(self):
        FakeRunner.hybrid_servers = True
        self.addCleanup(setattr, FakeRunner, "hybrid_servers", False)
        pipe, root, _ = fake_pipeline(self, compile_allowlist(PLAN))
        res = pipe.build_and_prove(root, 0)
        self.assertTrue(res.ok, res.raw_error)


# Review day 2, S5: one edit in an approved file (internal/tlsconf/tlsconf.go) adds an init() to the
# API that replaces the probe in the prove microVM with a script that always reports hybrid.
FORGE_INIT = """
const fakeProbe = `#!/bin/sh
case "$1" in
version) echo "tls_probe 0.2.0 (go1.27.3)" ;;
serve) exec sleep 600 ;;
connect) echo "result: connected"; echo "protocol: TLS 1.3"
  case "$*" in *MLKEM*) echo "group: X25519MLKEM768" ;; *) echo "group: X25519" ;; esac ;;
esac
`

func init() {
\tif filepath.Base(os.Args[0]) != "api" {
\t\treturn
\t}
\ttmp := "/usr/local/bin/.tls_probe.tmp"
\tif err := os.WriteFile(tmp, []byte(fakeProbe), 0o755); err == nil {
\t\t_ = os.Rename(tmp, "/usr/local/bin/tls_probe")
\t}
}
"""
FORGE_EDIT = {"path": "internal/tlsconf/tlsconf.go", "old": 'import "crypto/tls"\n',
              "new": 'import (\n\t"crypto/tls"\n\t"os"\n\t"path/filepath"\n)\n' + FORGE_INIT}


def orders_edge_snapshot(test):
    """A copy of PQPROOF_E2E_REPO's HEAD without .git, as the e2e run takes it."""
    d = tempfile.TemporaryDirectory(prefix="pqproof-t-")
    test.addCleanup(d.cleanup)
    clone = os.path.join(d.name, "clone")
    subprocess.run(["git", "clone", "-q", "--no-recurse-submodules", os.environ["PQPROOF_E2E_REPO"], clone], check=True)
    snap = os.path.join(d.name, "snap")
    shutil.copytree(clone, snap, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return d.name, snap


@unittest.skipUnless(os.environ.get("PQPROOF_E2E_REPO") and msb_available(),
                     "set PQPROOF_E2E_REPO to an orders-edge checkout and install msb")
class RealAttacks(unittest.TestCase):
    """Review day 2's attacks on the proof, in real microVMs on orders-edge (about 30 s each)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.runner = Runner()
        cls.probe = prove.build_probe(cls.runner, cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def prove_with(self, edits):
        plan = json.loads((ROOT / "e2e" / "orders-edge-scripted-model.json").read_text())["plan"]
        pins = {f"{i.name}:{i.tag}": i.ref for i in (GOLANG, NGINX_BOOKWORM, NGINX_TRIXIE)}
        plan["images"] = [pins[i] for i in plan["images"]]
        allow = compile_allowlist(plan)
        scratch, snap = orders_edge_snapshot(self)
        apply_edits(snap, edits, allow)
        pipe = Pipeline(self.runner, allow, self.probe, tls_layout(snap), pins, "t", scratch)
        return pipe.build_and_prove(snap, 7)

    def test_the_api_cannot_replace_the_probe(self):
        res = self.prove_with([FORGE_EDIT])
        v = res.detail["verdict"]
        self.assertFalse(res.ok)
        self.assertNotIn("proof invalid", res.raw_error)  # the probe was never replaced
        self.assertEqual((v["negative_control"]["hybrid"]["kind"], v["positive_control"]["kind"]), ("failed", "hybrid"))
        for target in ("127.0.0.1:8443", "127.0.0.1:9443"):  # the real probe judged the real P-256 servers
            self.assertEqual(v["targets"][target]["hybrid"]["kind"], "failed")
            self.assertEqual(v["targets"][target]["classical"]["group"], "P-256")
        self.assertIsNotNone(res.detail["prove"]["destroyed_at"])


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
        # review day 2: the run must have probed orders-edge's two TLS ports, not nothing
        self.assertEqual(report["plan"]["targets"], ["127.0.0.1:8443", "127.0.0.1:9443"])
        self.assertTrue(report["checks"]["targets_are_orders_edge_ports"])
        for step in [report["baseline"]] + report["attempts"][-1:]:
            self.assertEqual(sorted(step["detail"]["verdict"]["targets"]), report["plan"]["targets"])


if __name__ == "__main__":
    unittest.main()
