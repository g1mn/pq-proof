"""receipt: the hashed receipt of a run, and verify-receipt, which recomputes every hash.

The report here comes from the real pipeline code with fake microVMs (test_pipeline's FakeRunner):
a classical-only baseline, a first attempt refused for weakening TLS, and a second attempt whose
servers negotiate X25519MLKEM768. The e2e test (test_pipeline.EndToEnd) builds one from a real run.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from pqproof import pipeline, prove, receipt
from pqproof.images import GOLANG
from pqproof.loop import BuildResult, ScriptedModel, run_loop
from pqproof.pipeline import Layout, Pipeline, session_record
from pqproof.plan import compile_allowlist
from pqproof.sandbox import captured
from pqproof.scan import scan
from test_pipeline import GO, NG, PLAN, FakeRunner

ROOT = pathlib.Path(__file__).resolve().parent.parent
F1 = ROOT / "tests" / "fixtures" / "f1"
SCRIPTED = json.loads((ROOT / "e2e" / "orders-edge-scripted-model.json").read_text())
CANARY_EVENT = {"kind": "tcp", "proto": "tcp", "dest": "203.0.113.7:80", "bytes": 253, "sha256": "d" * 64,
                "canaries": ["CANARY-0001"], "t": 1793805140.964555,
                "preview": "POST /v1/report HTTP/1.1\r\nHost: 203.0.113.7\r\n\r\n{\"canary\":\"CANARY-0001\"}\x1b[2J"}


class FakeSink:
    """Sinkhole stand-in: the canary arrives while the first build step runs, plus 2 events over the cap."""

    def __init__(self):
        self.windows = 0

    def take(self):
        self.windows += 1
        return ([dict(CANARY_EVENT)], 2) if self.windows == 2 else ([], 0)


def make_run(d):
    """(report, log_dir) shaped like e2e/orders_edge.py's, from fake microVMs."""
    log_dir = os.path.join(d, "logs")
    sink, runner = FakeSink(), FakeRunner(probe_bytes=b"")
    snap = shutil.copytree(F1, os.path.join(d, "snap"), symlinks=True)
    plan = json.loads(json.dumps(PLAN))
    allow = compile_allowlist(plan)
    report = {"started_at": 1793805100.25, "model": {"kind": "scripted", "note": "n", "file": "f.json"},
              "repo": {"path": "../orders-edge", "url": "https://deploy:tok@github.com/g1mn/orders-edge.git",
                       "commit": "7c7e501" + "0" * 33, "tree": "f196979a" + "0" * 32},
              "cbom_before": [r.to_json() for r in scan(snap)], "plan": plan,
              "images": [{"requested": "golang:1.27-bookworm", "pinned": GO, "digest": GO.partition("@")[2], "architecture": "arm64"},
                         {"requested": "nginx:1.30-trixie", "pinned": NG, "digest": NG.partition("@")[2], "architecture": "arm64"}]}
    with runner.session(prove.build_allowlist(GOLANG.ref), "probe", "build", GOLANG.ref, prove.PROBE_BUILD_LIMITS) as s:
        s.exec(list(prove.BUILD_PROBE))
    report["probe_build"] = session_record(s, sink, log_dir)
    probe = prove.Probe("tls_probe", prove.PROBE_VERSION, hashlib.sha256(b"").hexdigest(), "0" * 64, GOLANG.ref, os.devnull)
    report["probe"] = probe.to_json()
    lay = Layout("nginx/nginx.conf", "/etc/orders-edge/tls", "orders-edge.local", "localhost,127.0.0.1", "/run/x.pid")
    pipe = Pipeline(runner, allow, probe, lay, {"golang:1.27-bookworm": GO, "nginx:1.30-trixie": NG}, "t",
                    os.path.join(d, "scratch"), sink, log_dir=log_dir)
    os.makedirs(os.path.join(d, "scratch"))
    (pathlib.Path(snap) / "Dockerfile").write_text("FROM golang:1.27-bookworm AS build\nFROM nginx:1.30-trixie\n")
    base = pipe.build_and_prove(snap, 0)
    report["baseline"] = {"ok": base.ok, "raw_error": base.raw_error, "detail": base.detail}

    def build(workdir, n):
        FakeRunner.hybrid_servers = True
        try:
            return pipe.build_and_prove(workdir, n)
        finally:
            FakeRunner.hybrid_servers = False

    weak = SCRIPTED["attempts"][-1][:3] + [{"path": "internal/tlsconf/tlsconf.go", "old": "MinVersion:",
                                            "new": "InsecureSkipVerify: true,\n\t\tMinVersion:"}]
    allow = compile_allowlist(dict(plan, edits=[{"path": e["path"], "why": "w"} for e in SCRIPTED["attempts"][-1]]))
    outcome = run_loop(ScriptedModel([weak, SCRIPTED["attempts"][-1][:3]]), snap, allow, build, os.path.join(d, "scratch"))
    report["attempts"] = [{"number": a.number, "edits": a.edits, "diff": a.diff, "ok": a.result.ok,
                           "raw_error": a.result.raw_error, "detail": a.result.detail} for a in outcome.attempts]
    report["tls_weakening_refused"] = [1]
    report["cbom_after"] = [r.to_json() for r in scan(outcome.workdir)]
    report["host_commands"] = [["git", "clone", "-q", "../orders-edge", "/tmp/x"], ["msb", "rm", "--force", "-q", "x"]]
    report["checks"] = {"host_build_commands": 0, "guest_build_commands": 7, "canaries_in_sinkhole": ["CANARY-0001"],
                        "every_sandbox_destroyed": True}
    report["passed"] = outcome.ok
    report["phases"] = [{"name": "plan", "started_at": 1793805100.5, "ended_at": 1793805101.0}]
    report["finished_at"] = 1793805190.0
    return json.loads(json.dumps(report, default=str)), log_dir


class Receipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.report, cls.log_dir = make_run(cls.tmp.name)
        cls.dir = os.path.join(cls.tmp.name, "receipt")
        cls.receipt = receipt.build(cls.report, cls.log_dir, cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def copy(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return shutil.copytree(self.dir, os.path.join(d.name, "r"), symlinks=True)

    def failures(self, root):
        return [w for ok, w in receipt.verify(root) if not ok]

    def test_a_fresh_receipt_verifies(self):
        self.assertEqual(self.failures(self.dir), [])
        self.assertRegex(self.receipt["receipt_id"], "^[0-9a-f]{64}$")
        on_disk = json.loads(pathlib.Path(self.dir, "receipt.json").read_text())
        self.assertEqual(on_disk, self.receipt)
        self.assertEqual(receipt.validate(on_disk, receipt.SCHEMA), [])

    def test_design_fields_are_there(self):
        r = self.receipt
        for key in ("receipt_id", "repo", "started_at", "destroyed_at", "sandboxes", "probe", "cbom", "patch", "proofs",
                    "not_fixed", "model"):
            self.assertIn(key, r)
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["patch"]["attempt"], 2)
        self.assertEqual(r["patch"]["files"], ["go.mod", "internal/tlsconf/tlsconf.go", "nginx/nginx.conf"])
        self.assertEqual(r["attempts"][0]["outcome"], "refused before any build: the patch weakens TLS")
        self.assertTrue(any("InsecureSkipVerify" in w for w in r["attempts"][0]["tls_weakening"]))
        self.assertIn("JWT", " ".join(n["item"] for n in r["not_fixed"]))
        self.assertEqual(r["model"]["provider"], "none: scripted edits written by hand, no model call")

    def test_proofs_cover_controls_targets_and_tests(self):
        by = {(p["step"], p["name"]): p for p in self.receipt["proofs"]}
        final = by[("attempt 2", "127.0.0.1:8443 (nginx): hybrid-only client")]
        self.assertEqual((final["expected"], final["actual"], final["ok"]), ("X25519MLKEM768", "X25519MLKEM768 (hybrid)", True))
        base = by[("baseline", "127.0.0.1:9443 (api): hybrid-only client")]
        self.assertTrue(base["actual"].startswith("no connection") and base["ok"])
        self.assertTrue(by[("attempt 2", "127.0.0.1:9443 (api): classical client")]["ok"])
        self.assertIn(("attempt 2", "negative control: hybrid-only client to the X25519-only reference server"), by)
        self.assertIn(("baseline", "repository tests: make test"), by)
        self.assertTrue(all(p["ok"] for p in self.receipt["proofs"]), [p for p in self.receipt["proofs"] if not p["ok"]])
        for p in self.receipt["proofs"]:  # each proof's log is an artifact with that hash
            data = pathlib.Path(self.dir, p["log"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), p["log_sha256"])
            self.assertTrue(data.decode().startswith("$ " + " ".join(p["command"])))

    def test_egress_is_split_by_step_and_by_what_reached_the_sinkhole(self):
        sb = {s["step"]: s for s in self.receipt["sandboxes"]}
        self.assertEqual(list(sb)[:3], ["probe build", "baseline build", "baseline prove"])
        hit = sb["baseline build"]["egress"]
        self.assertEqual([e["canaries"] for e in hit["reached_sinkhole"]], [["CANARY-0001"]])
        self.assertEqual(hit["reached_sinkhole_not_kept"], 2)
        self.assertEqual(hit["dropped_by_policy"], "not counted")
        preview = hit["reached_sinkhole"][0]["preview"]
        self.assertNotIn("\x1b", preview)  # control characters are replaced; HTTP line breaks stay line breaks
        self.assertEqual((preview.count("\ufffd"), preview.count("\r"), preview.count("\n")), (1, 0, 3))
        self.assertEqual(sum(len(s["egress"]["reached_sinkhole"]) for s in sb.values()), 1)
        c = self.receipt["containment"]
        self.assertEqual((c["canaries_caught"], c["reached_sinkhole"], c["reached_sinkhole_not_kept"]), (["CANARY-0001"], 1, 2))
        self.assertEqual(c["sandboxes_destroyed"], c["sandboxes"])

    def test_no_signed_wording_and_no_external_references(self):
        for name in ("receipt.json", "receipt.html"):
            text = pathlib.Path(self.dir, name).read_text()
            self.assertEqual(len(re.findall("signed", text, re.I)), 0, name)
        page = pathlib.Path(self.dir, "receipt.html").read_text()
        self.assertNotRegex(page, r"(?i)<(?:link|img|iframe|object|embed)\b|\bsrc\s*=|url\(|@import")
        for href in re.findall(r'href="([^"]*)"', page):
            self.assertRegex(href, r"^artifacts/[A-Za-z0-9_./-]+$")
        self.assertIn(receipt.SCRIPT_CSP, page)  # the one inline script is allowed by its hash only
        self.assertIn('data-theme="dark"', page)

    def test_every_artifact_byte_is_covered(self):
        cases = {
            "a log changed": lambda r: pathlib.Path(r, self.receipt["proofs"][0]["log"]).write_text("forged\n"),
            "the verdict changed": lambda r: self.rewrite(r, lambda j: j.update(verdict="fail")),
            "an extra file": lambda r: pathlib.Path(r, "artifacts", "extra.txt").write_text("x"),
            "receipt.html changed": lambda r: pathlib.Path(r, "receipt.html").write_text("<p>PASS</p>"),
            "a field the schema does not know": lambda r: self.rewrite(r, lambda j: j.update(signature="x"), rehash=True),
            "a hash in the receipt rehashed": lambda r: self.rewrite(
                r, lambda j: j["proofs"][0].update(log_sha256="0" * 64), rehash=True),
            "the CBOM rows changed": lambda r: self.rewrite(r, lambda j: j["cbom"]["before"].pop(), rehash=True),
        }
        for name, tamper in cases.items():
            with self.subTest(name):
                root = self.copy()
                tamper(root)
                self.assertNotEqual(self.failures(root), [], name)

    def rewrite(self, root, change, rehash=False):
        p = pathlib.Path(root, "receipt.json")
        j = json.loads(p.read_text())
        change(j)
        if rehash:
            j["receipt_id"] = receipt.compute_id(j)
            pathlib.Path(root, "receipt.html").write_text(receipt.render_html(j))
        p.write_text(json.dumps(j))

    def test_a_symlinked_artifact_is_not_followed(self):
        root = self.copy()
        target = self.receipt["proofs"][0]["log"]
        outside = pathlib.Path(root).parent / "outside.log"
        shutil.copy(pathlib.Path(root, target), outside)  # same bytes, so only the link itself is wrong
        os.unlink(pathlib.Path(root, target))
        os.symlink(outside, pathlib.Path(root, target))
        bad = self.failures(root)
        self.assertTrue(any(target in w and "cannot be read" in w for w in bad), bad)

    def test_cli(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        ok = subprocess.run([sys.executable, "-m", "pqproof", "verify-receipt", self.dir], capture_output=True, text=True, env=env)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn(self.receipt["receipt_id"], ok.stdout)
        root = self.copy()
        pathlib.Path(root, self.receipt["patch"]["diff"]).write_text("")
        bad = subprocess.run([sys.executable, "-m", "pqproof", "verify-receipt", root], capture_output=True, text=True, env=env)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("FAIL artifacts/attempt-2.diff", bad.stdout)

    # Day-3 review (11-05) -------------------------------------------------------------------
    def test_the_repository_is_named_by_public_url_commit_and_tree(self):
        # the VX1 receipt said /opt/pqproof/orders-edge/current and a host-only commit: no reader
        # could match it with the repository it came from
        self.assertEqual(self.receipt["repo"], {"url": "https://github.com/g1mn/orders-edge", "path": "../orders-edge",
                                                "commit": "7c7e501" + "0" * 33, "tree": "f196979a" + "0" * 32})
        for given, want in (("git@github.com:g1mn/orders-edge.git", "https://github.com/g1mn/orders-edge"),
                            ("ssh://git@github.com/g1mn/orders-edge", "https://github.com/g1mn/orders-edge"),
                            ("https://x:y@example.com:8443/a/b.git", "https://example.com:8443/a/b"),
                            ("/opt/pqproof/orders-edge/current", None), ("file:///tmp/x", None), (None, None),
                            ("http://example.com/a", None), ("https://example.com/a b", None)):
            with self.subTest(given=given):
                self.assertEqual(receipt.public_url(given), want)

    def test_artifact_paths_stay_inside_the_receipt(self):
        root = self.copy()
        outside = pathlib.Path(root).parent / "report.json"
        outside.write_text('{"not": "part of the receipt"}\n')
        digest = hashlib.sha256(outside.read_bytes()).hexdigest()
        for path in ("artifacts/../../report.json", "artifacts/./x", "artifacts/logs/../../../report.json"):
            with self.subTest(path):
                r = self.copy()
                (pathlib.Path(r).parent / "report.json").write_bytes(outside.read_bytes())
                self.rewrite(r, lambda j: j["artifacts"].append({"path": path, "bytes": outside.stat().st_size, "sha256": digest}),
                             rehash=True)
                bad = self.failures(r)
                self.assertNotEqual(bad, [])
                self.assertFalse([w for w in bad if digest in w and "the receipt says" not in w], bad)
        with self.assertRaises((OSError, ValueError)):
            receipt._read_nofollow(root, "artifacts/../../report.json")

    def test_a_file_anywhere_in_the_receipt_must_be_listed(self):
        for rel in ("extra.html", "notes/a.txt", "artifacts/logs/extra.log"):
            with self.subTest(rel):
                root = self.copy()
                pathlib.Path(root, rel).parent.mkdir(parents=True, exist_ok=True)
                pathlib.Path(root, rel).write_text("x")
                self.assertTrue(any(rel in w for w in self.failures(root)), rel)

    def final_hybrid(self, j):
        return next(p for p in j["proofs"] if p["step"] == "attempt 2" and p["name"].startswith("127.0.0.1:8443")
                    and "hybrid-only client" in p["name"])

    def test_the_verdict_and_counts_agree_with_the_record(self):
        # the page says the verdict comes from the handshakes and exit codes; verify-receipt now checks it
        def failed_proof(j):
            self.final_hybrid(j).update(actual="no connection (handshake failure)", ok=False)

        def undestroyed(j):
            j["sandboxes"][0]["destroyed_at"] = None

        cases = {"verdict pass with a failed final proof": failed_proof,
                 "verdict pass without a patch": lambda j: j.update(patch=None),
                 "a patch from an attempt that failed": lambda j: j["patch"].update(attempt=1),
                 "a microVM not destroyed, counted as destroyed": undestroyed,
                 "fewer microVMs counted": lambda j: j["containment"].update(sandboxes=1),
                 "sinkhole events not counted": lambda j: j["containment"].update(reached_sinkhole=0),
                 "events over the cap not counted": lambda j: j["containment"].update(reached_sinkhole_not_kept=0),
                 "a canary dropped from the summary": lambda j: j["containment"].update(canaries_caught=[]),
                 "a refused attempt left out": lambda j: j["containment"].update(tls_weakening_refused=[]),
                 "host build commands with a pass": lambda j: j["containment"].update(host_build_commands=1)}
        for name, change in cases.items():
            with self.subTest(name):
                root = self.copy()
                self.rewrite(root, change, rehash=True)
                self.assertNotEqual(self.failures(root), [], name)
        root = self.copy()  # a failed run may have passing proofs: that is no contradiction
        self.rewrite(root, lambda j: j.update(verdict="fail"), rehash=True)
        self.assertEqual(self.failures(root), [])


class Canonical(unittest.TestCase):
    """receipt_id must come out the same in a verifier written in another language (RFC 8785)."""

    def test_numbers_are_written_as_ecmascript_writes_them(self):
        for x, want in ((0.0, "0"), (-0.0, "0"), (5e-06, "0.000005"), (1e-07, "1e-7"), (0.015523, "0.015523"),
                        (1e21, "1e+21"), (1e20, "100000000000000000000"), (123.0, "123"), (0.1, "0.1"),
                        (1.5e300, "1.5e+300"), (-2.5, "-2.5"), (7, "7"), (1.2345678901234567e-05, "0.000012345678901234568"),
                        (True, "true"), (None, "null")):
            with self.subTest(x=x):
                self.assertEqual(receipt.canonical(x), want.encode())
        self.assertEqual(receipt.canonical({"b": [1.0, "\u00e9\n"], "a": {}}), '{"a":{},"b":[1,"\u00e9\\n"]}'.encode())

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_receipt_id_matches_a_javascript_verifier(self):
        js = ("let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s);delete r.receipt_id;"
              "const c=v=>Array.isArray(v)?v.map(c):v&&typeof v==='object'?Object.keys(v).sort().reduce((o,k)=>(o[k]=c(v[k]),o),{}):v;"
              "process.stdout.write(require('crypto').createHash('sha256').update(JSON.stringify(c(r)),'utf8').digest('hex'))})")
        with tempfile.TemporaryDirectory() as d:
            report, log_dir = make_run(d)
            r = receipt.build(report, log_dir, os.path.join(d, "receipt"))
        for cost in (0.015523, 0.0, 5e-06, 1e-07, 12.5):
            with self.subTest(cost=cost):
                r2 = dict(r, model=dict(r["model"], cost_usd=cost))
                node = subprocess.run(["node", "-e", js], input=json.dumps(r2), capture_output=True, text=True, check=True).stdout
                self.assertEqual(receipt.compute_id(r2), node)


class Schema(unittest.TestCase):
    def test_validate_names_each_problem(self):
        schema = receipt.strict(a=receipt.SHA, b={"type": "array", "minItems": 1, "items": receipt.INT})
        self.assertEqual(receipt.validate({"a": "0" * 64, "b": [1]}, schema), [])
        problems = receipt.validate({"a": "xyz", "b": [True], "c": 1}, schema)
        self.assertEqual(len(problems), 3, problems)  # pattern, bool is not an integer, unexpected field
        self.assertEqual(receipt.validate({"b": []}, schema), ["receipt: missing a", "receipt.b: needs at least 1 items"])


class ExecLogs(unittest.TestCase):
    def test_a_log_names_the_command_and_every_byte_s_digest(self):
        with tempfile.TemporaryDirectory() as d:
            big = captured(b"a" * 10, b"z" * 10, total=5000, sha256="f" * 64)
            e = type("E", (), {"argv": ["make", "test"], "exit_code": 2, "timed_out": False, "stdout": big, "stderr": "err"})
            rel = pipeline.write_exec_log(d, "pq-1-e2e-build-a0-abcd", 3, e)
            self.assertEqual(rel, "pq-1-e2e-build-a0-abcd/03-make.log")
            text = pathlib.Path(d, rel).read_text()
        self.assertTrue(text.startswith("$ make test\nexit code: 2\n--- stdout: 5000 bytes, sha256 " + "f" * 64))
        self.assertIn("[... 4980 bytes not kept ...]", text)
        self.assertIn(f"--- stderr: 3 bytes, sha256 {hashlib.sha256(b'err').hexdigest()}\nerr\n", text)


if __name__ == "__main__":
    unittest.main()
