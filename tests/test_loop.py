"""loop: the edit applier (allowlist, realpath, O_NOFOLLOW), the 3-attempt retry loop, the models,
and image tag resolution."""
import json
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest

from helpers import msb_available
from pqproof.images import resolve
from pqproof.inference import parse_reply
from pqproof.loop import (MAX_ATTEMPTS, MAX_EDIT_FILE, PATCH_TOOL, BuildResult, EditError, InferenceModel, ScriptedModel,
                          apply_edits, run_loop, unified_diff)
from pqproof.plan import Allowlist, PlanError
from pqproof.sandbox import MSB


def allow_paths(*paths):
    return Allowlist(commands=frozenset(), paths=frozenset(paths), images=frozenset())


class Snapshot(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name, "snap")
        self.outside = pathlib.Path(tmp.name, "outside")
        (self.root / "nginx").mkdir(parents=True)
        self.outside.mkdir()
        (self.root / "nginx" / "nginx.conf").write_text("ssl_ecdh_curve prime256v1;\n")
        (self.root / "go.mod").write_text("module m\n\ngo 1.22\n")
        (self.outside / "secret.conf").write_text("ssl_ecdh_curve prime256v1;\n")


class ApplyEdits(Snapshot):
    def test_applies_and_diffs(self):
        changed = apply_edits(str(self.root), [
            {"path": "nginx/nginx.conf", "old": "prime256v1", "new": "X25519MLKEM768:X25519:prime256v1"},
            {"path": "go.mod", "old": "go 1.22", "new": "go 1.27"},
            {"path": "go.mod", "old": "module m", "new": "module m2"},  # a second edit to the same file
        ], allow_paths("nginx/nginx.conf", "go.mod"))
        self.assertEqual((self.root / "go.mod").read_text(), "module m2\n\ngo 1.27\n")
        diff = unified_diff(changed)
        self.assertIn("-go 1.22\n+go 1.27\n", diff)
        self.assertIn("--- a/nginx/nginx.conf\n+++ b/nginx/nginx.conf\n", diff)
        self.assertEqual(changed["go.mod"][0], "module m\n\ngo 1.22\n")

    def refused(self, edit, allow=None):
        with self.assertRaises(EditError) as cm:
            apply_edits(str(self.root), [edit], allow or allow_paths(edit.get("path", "")))
        return str(cm.exception)

    def test_path_must_be_in_the_plan(self):
        self.assertIn("not in the approved plan", self.refused(
            {"path": "go.mod", "old": "go 1.22", "new": "go 1.27"}, allow_paths("nginx/nginx.conf")))

    def test_dotdot_absolute_and_git_are_refused(self):
        for path in ("../outside/secret.conf", "/etc/passwd", ".git/config", "nginx/../../outside/secret.conf"):
            with self.subTest(path=path):
                self.refused({"path": path, "old": "a", "new": "b"})

    def test_symlinked_file_pointing_outside_is_refused(self):
        os.symlink(self.outside / "secret.conf", self.root / "nginx" / "edge.conf")
        self.assertIn("symlink", self.refused({"path": "nginx/edge.conf", "old": "prime256v1", "new": "X"}))
        self.assertEqual((self.outside / "secret.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_symlinked_directory_pointing_outside_is_refused(self):
        os.symlink(self.outside, self.root / "conf")
        self.assertIn("symlink", self.refused({"path": "conf/secret.conf", "old": "prime256v1", "new": "X"}))
        self.assertEqual((self.outside / "secret.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_symlink_inside_the_snapshot_is_refused_too(self):
        os.symlink("nginx.conf", self.root / "nginx" / "alias.conf")
        self.refused({"path": "nginx/alias.conf", "old": "prime256v1", "new": "X"})
        self.assertEqual((self.root / "nginx" / "nginx.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_o_nofollow_catches_a_symlink_the_realpath_check_missed(self):
        # Simulate a symlink appearing after the realpath check: call the opener directly.
        from pqproof.loop import _open_nofollow
        os.symlink(self.outside / "secret.conf", self.root / "late.conf")
        with self.assertRaises(OSError):
            _open_nofollow(str(self.root), "late.conf", os.O_RDWR)
        os.symlink(self.outside, self.root / "latedir")
        with self.assertRaises(OSError):
            _open_nofollow(str(self.root), "latedir/secret.conf", os.O_RDWR)

    def test_old_must_occur_exactly_once(self):
        (self.root / "go.mod").write_text("go 1.22\ngo 1.22\n")
        self.assertIn("exactly once", self.refused({"path": "go.mod", "old": "go 1.22", "new": "go 1.27"}))
        self.assertIn("exactly once", self.refused({"path": "go.mod", "old": "nothing", "new": "x"}))
        self.assertIn("exactly once", self.refused({"path": "go.mod", "old": "", "new": "x"}))

    def test_malformed_edits(self):
        for edit in ({"path": "go.mod", "old": "go"}, {"path": "go.mod", "old": "go", "new": 1},
                     {"path": "go.mod", "old": "go", "new": "x", "mode": "0777"}, "go.mod"):
            with self.subTest(edit=edit), self.assertRaises(EditError):
                apply_edits(str(self.root), [edit], allow_paths("go.mod"))
        self.assertRaises(EditError, apply_edits, str(self.root), {"path": "go.mod"}, allow_paths("go.mod"))

    def test_directory_and_missing_file(self):
        self.refused({"path": "nginx", "old": "a", "new": "b"})
        self.refused({"path": "missing.conf", "old": "a", "new": "b"})

    # review day 2: odd files at an approved path must be a refused edit, never a crash or a write elsewhere
    def test_hard_link_is_refused(self):
        os.unlink(self.root / "nginx" / "nginx.conf")
        os.link(self.outside / "secret.conf", self.root / "nginx" / "nginx.conf")
        self.assertIn("hard link", self.refused({"path": "nginx/nginx.conf", "old": "prime256v1", "new": "PWNED"}))
        self.assertEqual((self.outside / "secret.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_fifo_is_refused_without_blocking(self):
        os.unlink(self.root / "nginx" / "nginx.conf")
        os.mkfifo(self.root / "nginx" / "nginx.conf")
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("msg", self.refused({"path": "nginx/nginx.conf", "old": "a", "new": "b"})),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "apply_edits blocked on a FIFO")
        self.assertIn("not a regular file", box.get("msg", ""))

    def test_non_utf8_file_is_refused(self):
        (self.root / "nginx" / "nginx.conf").write_bytes(b"ssl_ecdh_curve prime256v1; \xff\xfe\n")
        self.assertIn("UTF-8", self.refused({"path": "nginx/nginx.conf", "old": "prime256v1", "new": "X"}))

    def test_result_size_is_capped(self):
        big = "x" * (MAX_EDIT_FILE + 1)
        self.assertIn("bytes", self.refused({"path": "nginx/nginx.conf", "old": "prime256v1", "new": big}))
        self.assertEqual((self.root / "nginx" / "nginx.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_odd_files_are_a_failed_attempt_not_a_crash(self):
        (self.root / "nginx" / "nginx.conf").write_bytes(b"\xff prime256v1\n")
        with tempfile.TemporaryDirectory() as scratch:
            out = run_loop(ScriptedModel([[{"path": "nginx/nginx.conf", "old": "prime256v1", "new": "X"}]]), str(self.root),
                           allow_paths("nginx/nginx.conf"), lambda w, n: BuildResult(ok=True), scratch)
        self.assertFalse(out.ok)
        self.assertTrue(out.attempts[0].result.raw_error.startswith("edit refused"))


GOOD = [{"path": "go.mod", "old": "go 1.22", "new": "go 1.27"}]
BAD = [{"path": "go.mod", "old": "go 1.22", "new": "go 1.99"}]


class Loop(Snapshot):
    def run_with(self, model, build):
        with tempfile.TemporaryDirectory() as scratch:
            out = run_loop(model, str(self.root), allow_paths("go.mod", "nginx/nginx.conf"), build, scratch,
                           context={"cbom": []})
            files = {a.number: pathlib.Path(scratch, f"attempt-{a.number}", "go.mod").read_text()
                     for a in out.attempts if pathlib.Path(scratch, f"attempt-{a.number}").exists()}
        return out, files

    def test_first_patch_fails_second_succeeds(self):
        model, builds = ScriptedModel([BAD, GOOD]), []

        def build(workdir, n):
            builds.append(n)
            text = pathlib.Path(workdir, "go.mod").read_text()
            if "go 1.99" in text:
                return BuildResult(ok=False, raw_error="go: go.mod requires go >= 1.99 (running go 1.27.3; GOTOOLCHAIN=local)")
            return BuildResult(ok=True)

        out, files = self.run_with(model, build)
        self.assertTrue(out.ok)
        self.assertEqual(len(out.attempts), 2)
        self.assertEqual(builds, [1, 2])
        # The raw error of attempt 1 is exactly what the model saw at attempt 2.
        self.assertEqual(model.calls, [(1, None), (2, "go: go.mod requires go >= 1.99 (running go 1.27.3; GOTOOLCHAIN=local)")])
        self.assertIn("+go 1.27", out.attempts[1].diff)
        # Each attempt starts from the original snapshot, not from the failed one.
        self.assertEqual(files, {1: "module m\n\ngo 1.99\n", 2: "module m\n\ngo 1.27\n"})
        self.assertEqual((self.root / "go.mod").read_text(), "module m\n\ngo 1.22\n")

    def test_never_a_fourth_attempt(self):
        model, builds = ScriptedModel([BAD]), []
        out, _ = self.run_with(model, lambda w, n: builds.append(n) or BuildResult(ok=False, raw_error=f"fail {n}"))
        self.assertEqual(MAX_ATTEMPTS, 3)
        self.assertFalse(out.ok)
        self.assertEqual([a.number for a in out.attempts], [1, 2, 3])
        self.assertEqual(builds, [1, 2, 3])
        self.assertEqual([c[0] for c in model.calls], [1, 2, 3])
        self.assertEqual(model.calls[2][1], "fail 2")

    def test_refused_edit_is_a_failed_attempt_without_a_build(self):
        os.symlink(self.outside / "secret.conf", self.root / "nginx" / "edge.conf")
        escape = [{"path": "nginx/edge.conf", "old": "prime256v1", "new": "X"}]
        model, builds = ScriptedModel([escape, GOOD]), []
        with tempfile.TemporaryDirectory() as scratch:
            allow = allow_paths("go.mod", "nginx/edge.conf")
            out = run_loop(model, str(self.root), allow, lambda w, n: builds.append(n) or BuildResult(ok=True), scratch)
        self.assertTrue(out.ok)
        self.assertEqual(builds, [2])
        self.assertIn("edit refused", model.calls[1][1])
        self.assertEqual((self.outside / "secret.conf").read_text(), "ssl_ecdh_curve prime256v1;\n")

    def test_feedback_is_bounded(self):
        model = ScriptedModel([BAD])
        self.run_with(model, lambda w, n: BuildResult(ok=False, raw_error="x" * 100_000 + "TAIL"))
        self.assertEqual(len(model.calls[1][1]), 8000)
        self.assertTrue(model.calls[1][1].endswith("TAIL"))


class FakeClient:
    def __init__(self, bodies):
        self.bodies, self.seen = list(bodies), []

    def chat(self, messages, tools=None, **kw):
        self.seen.append(json.loads(json.dumps(messages)))
        return parse_reply(self.bodies.pop(0), tools)


def body(*calls):
    return {"choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "content": None, "tool_calls": [
        {"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
        for i, (n, a) in enumerate(calls)]}}]}


class Models(unittest.TestCase):
    def test_inference_model_reads_the_tool_call_and_feeds_back_raw_errors(self):
        client = FakeClient([body(("propose_edits", {"edits": BAD})), body(("propose_edits", {"edits": GOOD}))])
        m = InferenceModel(client, "You patch TLS settings.")
        self.assertEqual(m.propose(1, None, {"cbom": ["row"]}), BAD)
        self.assertEqual(m.propose(2, "RAW BUILD ERROR", None), GOOD)
        last_user = [msg for msg in client.seen[1] if msg["role"] == "user"][-1]["content"]
        self.assertIn("RAW BUILD ERROR", last_user)
        self.assertEqual([msg["role"] for msg in client.seen[1]], ["system", "user", "assistant", "tool", "user"])

    def test_inference_model_ignores_undeclared_tools_and_bad_arguments(self):
        client = FakeClient([body(("run_shell", {"cmd": "curl x"}), ("propose_edits", {"edits": GOOD, "extra": 1}))])
        self.assertEqual(InferenceModel(client, "s").propose(1, None, {}), [])

    def test_scripted_model_repeats_its_last_answer(self):
        m = ScriptedModel([BAD, GOOD])
        self.assertEqual([m.propose(n, None, None) for n in (1, 2, 3)], [BAD, GOOD, GOOD])

    def test_patch_tool_shape(self):
        self.assertEqual(PATCH_TOOL["function"]["parameters"]["required"], ["edits"])
        self.assertFalse(PATCH_TOOL["function"]["parameters"]["additionalProperties"])


class Resolve(unittest.TestCase):
    DIGEST = "sha256:" + "ab" * 32

    def fake(self, rc=0, digest=None):
        calls = []

        def run(argv, timeout=None):
            calls.append(argv)
            out = json.dumps({"digest": digest or self.DIGEST, "architecture": "arm64"}) if argv[1] == "image" else ""
            return subprocess.CompletedProcess(argv, rc, out, "pull failed" if rc else "")
        return run, calls

    def test_tag_becomes_name_tag_at_platform_digest(self):
        run, calls = self.fake()
        r = resolve("nginx:1.30-trixie", run)
        self.assertEqual(r.pinned, f"nginx:1.30-trixie@{self.DIGEST}")
        self.assertEqual(r.show(), f"nginx:1.30-trixie -> nginx:1.30-trixie@{self.DIGEST} (linux/arm64)")
        self.assertEqual(calls, [["msb", "pull", "-q", "nginx:1.30-trixie"],
                                 ["msb", "image", "inspect", "nginx:1.30-trixie", "--format", "json"],
                                 ["msb", "pull", "-q", f"nginx:1.30-trixie@{self.DIGEST}"]])

    def test_refuses_latest_untagged_other_registries_and_failures(self):
        for ref in ("nginx", "nginx:latest", "ghcr.io/x/nginx:1", "evil.example/library/nginx:1", "nginx:1@sha256:zz",
                    "nginx:1;rm"):
            with self.subTest(ref=ref), self.assertRaises(PlanError):
                resolve(ref, self.fake()[0])
        with self.assertRaises(PlanError):
            resolve("nginx:1.30-trixie", self.fake(rc=1)[0])
        with self.assertRaises(PlanError):
            resolve("nginx:1.30-trixie", self.fake(digest="sha256:short")[0])

    @unittest.skipUnless(msb_available(), "msb not installed or PQPROOF_MSB_TESTS=0")
    def test_real_msb_reports_the_platform_digest_for_an_index_pin(self):
        from pqproof.images import NGINX_TRIXIE
        from pqproof.sandbox import run_cmd
        if subprocess.run([MSB, "image", "inspect", NGINX_TRIXIE.ref], capture_output=True).returncode:
            self.skipTest(f"image not cached: msb pull {NGINX_TRIXIE.ref}")
        r = resolve(NGINX_TRIXIE.ref, run_cmd, msb=MSB)
        arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[r.architecture]
        self.assertEqual(r.digest, NGINX_TRIXIE.platforms[arch])
        self.assertNotEqual(r.digest, NGINX_TRIXIE.index)
        self.assertEqual(r.pinned, f"nginx:1.30-trixie@{r.digest}")


if __name__ == "__main__":
    unittest.main()
