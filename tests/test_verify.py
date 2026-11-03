"""verify: the TLS-weakening check on a patch (before/after text of each changed file)."""
import json
import pathlib
import shutil
import tempfile
import unittest

from pqproof.loop import BuildResult, ScriptedModel, apply_edits, run_loop
from pqproof.plan import Allowlist
from pqproof.verify import strip_comments, weakening

ROOT = pathlib.Path(__file__).resolve().parent.parent
F1 = ROOT / "tests" / "fixtures" / "f1"
SCRIPTED = json.loads((ROOT / "e2e" / "orders-edge-scripted-model.json").read_text())
NGINX = (F1 / "nginx" / "nginx.conf").read_text()
TLSCONF = (F1 / "internal" / "tlsconf" / "tlsconf.go").read_text()
GO_CLIENT = """package c

import ("crypto/tls"; "crypto/x509")

func client(pool *x509.CertPool) *tls.Config {
\treturn &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
"""

# (name, path, before, after): every one of these must be refused.
WEAKENING = [
    ("InsecureSkipVerify field", "internal/tlsconf/tlsconf.go", TLSCONF,
     TLSCONF.replace("MinVersion:", "InsecureSkipVerify: true,\n\t\tMinVersion:")),
    ("InsecureSkipVerify assignment", "internal/tlsconf/tlsconf.go", TLSCONF,
     TLSCONF.replace("\treturn &tls.Config{", "\tc := &tls.Config{}\n\tc.InsecureSkipVerify = true\n\treturn &tls.Config{")),
    ("VerifyPeerCertificate callback", "c/c.go", GO_CLIENT, GO_CLIENT.replace(
        "MinVersion:", "VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }, MinVersion:")),
    ("RootCAs dropped by a replaced tls.Config", "c/c.go", GO_CLIENT,
     GO_CLIENT.replace("RootCAs: pool, ", "")),
    ("TLS 1.0 allowed", "c/c.go", GO_CLIENT, GO_CLIENT.replace("tls.VersionTLS12", "tls.VersionTLS10")),
    ("client certs not verified", "s/s.go", "var a = tls.RequireAndVerifyClientCert\n", "var a = tls.VerifyClientCertIfGiven\n"),
    ("proxy_ssl_verify off", "nginx/nginx.conf", NGINX, NGINX.replace("proxy_ssl_verify on;", "proxy_ssl_verify off;")),
    ("proxy_ssl_verify on deleted (default off)", "nginx/nginx.conf", NGINX,
     NGINX.replace("            proxy_ssl_verify on;\n", "")),
    ("proxy_ssl_verify on commented out", "nginx/nginx.conf", NGINX,
     NGINX.replace("proxy_ssl_verify on;", "# proxy_ssl_verify on;")),
    ("proxy_ssl_trusted_certificate deleted", "nginx/nginx.conf", NGINX,
     NGINX.replace("            proxy_ssl_trusted_certificate /etc/orders-edge/tls/ca.pem;\n", "")),
    ("ssl_verify_client off", "nginx/edge.conf", "ssl_verify_client on;\nssl_client_certificate /a/ca.pem;\n",
     "ssl_verify_client off;\nssl_client_certificate /a/ca.pem;\n"),
    ("TLSv1.1 in ssl_protocols", "nginx/nginx.conf", NGINX,
     NGINX.replace("ssl_protocols       TLSv1.2 TLSv1.3;", "ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;")),
    ("rejectUnauthorized: false", "web/client.js", "const a = https.request({host});\n",
     "const a = https.request({host, rejectUnauthorized: false});\n"),
    ("NODE_TLS_REJECT_UNAUTHORIZED in a Dockerfile", "Dockerfile", "FROM node:22\n",
     "FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
    ("NODE_TLS_REJECT_UNAUTHORIZED in code", "web/index.js", "start();\n",
     "process.env[\"NODE_TLS_REJECT_UNAUTHORIZED\"] = \"0\";\nstart();\n"),
    ("verify=False", "tools/check.py", "requests.get(url)\n", "requests.get(url, verify=False)\n"),
    ("check_hostname = False", "tools/ctx.py", "ctx = ssl.create_default_context()\n",
     "ctx = ssl.create_default_context()\nctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\n"),
    ("curl -k", "Makefile", "health:\n\tcurl https://localhost:8443/\n", "health:\n\tcurl -k https://localhost:8443/\n"),
]


class Weakening(unittest.TestCase):
    def test_each_weakening_is_refused(self):
        for name, path, before, after in WEAKENING:
            with self.subTest(name):
                self.assertNotEqual(before, after)  # the replace above took
                self.assertTrue(weakening({path: (before, after)}), f"{name} passed")

    def test_the_scripted_migration_passes(self):
        # the e2e run's attempt 2 on the orders-edge fixture: groups, go line and runtime image only
        with tempfile.TemporaryDirectory() as d:
            snap = shutil.copytree(F1, pathlib.Path(d, "snap"), symlinks=True)
            edits = SCRIPTED["attempts"][-1]
            changed = apply_edits(str(snap), edits, Allowlist(frozenset(), frozenset(e["path"] for e in edits), frozenset()))
        self.assertEqual(sorted(changed), ["Dockerfile", "go.mod", "internal/tlsconf/tlsconf.go", "nginx/nginx.conf"])
        self.assertEqual(weakening(changed), [])

    def test_moving_or_tightening_a_setting_passes(self):
        moved = NGINX.replace("            proxy_ssl_verify on;\n", "").replace(
            "            proxy_ssl_name orders-api.internal;\n", "            proxy_ssl_name orders-api.internal;\n            proxy_ssl_verify on;\n")
        self.assertNotEqual(moved, NGINX)
        self.assertEqual(weakening({"nginx/nginx.conf": (NGINX, moved)}), [])
        tighter = NGINX.replace("ssl_protocols       TLSv1.2 TLSv1.3;", "ssl_protocols TLSv1.3;")
        self.assertEqual(weakening({"nginx/nginx.conf": (NGINX, tighter)}), [])
        # a comment that names a setting is not the setting
        self.assertEqual(weakening({"c/c.go": (GO_CLIENT, GO_CLIENT + "// never set InsecureSkipVerify here\n")}), [])

    def test_report_names_file_rule_and_counts(self):
        out = weakening({"nginx/nginx.conf": (NGINX, NGINX.replace("            proxy_ssl_verify on;\n", ""))})
        self.assertEqual(out, ["nginx/nginx.conf: proxy_ssl_verify on removed (nginx's default is off) (before 1, after 0)"])

    def test_comments_are_removed_but_urls_stay(self):
        self.assertEqual(strip_comments('u := "https://x" // RootCAs\n/* RootCAs */ a\n', "go"), 'u := "https://x" \n  a\n')
        self.assertEqual(strip_comments("a on; # proxy_ssl_verify on;\n", "nginx"), "a on; \n")


class Loop(unittest.TestCase):
    """Review day 2: run_loop called any edit the build accepted a success, so following the
    orders-edge README's injected note, or deleting `proxy_ssl_verify on;`, passed."""

    def run_edits(self, edits_by_attempt):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        snap = shutil.copytree(F1, pathlib.Path(d.name, "snap"), symlinks=True)
        scratch = pathlib.Path(d.name, "scratch")
        scratch.mkdir()
        paths = frozenset(e["path"] for a in edits_by_attempt for e in a)
        builds = []
        out = run_loop(ScriptedModel(edits_by_attempt), str(snap), Allowlist(frozenset(), paths, frozenset()),
                       lambda w, n: builds.append(n) or BuildResult(ok=True), str(scratch))
        return out, builds

    def test_a_weakening_patch_fails_without_a_build(self):
        injected = SCRIPTED["attempts"][-1] + [{"path": "internal/tlsconf/tlsconf.go", "old": "MinVersion:",
                                               "new": "InsecureSkipVerify: true,\n\t\tMinVersion:"}]
        deleted = SCRIPTED["attempts"][-1] + [{"path": "nginx/nginx.conf", "old": "            proxy_ssl_verify on;\n", "new": ""}]
        for name, edits in (("README note followed", injected), ("verify line deleted", deleted)):
            with self.subTest(name):
                out, builds = self.run_edits([edits])
                self.assertFalse(out.ok)
                self.assertEqual(builds, [])  # never built
                self.assertEqual(len(out.attempts), 3)
                self.assertIn("patch weakens TLS", out.attempts[0].result.raw_error)
                self.assertNotEqual(out.attempts[0].diff, "")  # the refused diff stays in the record

    def test_the_raw_reason_goes_back_and_a_clean_patch_then_passes(self):
        bad = SCRIPTED["attempts"][-1] + [{"path": "nginx/nginx.conf", "old": "proxy_ssl_verify on;", "new": "proxy_ssl_verify off;"}]
        model = ScriptedModel([bad, SCRIPTED["attempts"][-1]])
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        snap = shutil.copytree(F1, pathlib.Path(d.name, "snap"), symlinks=True)
        scratch = pathlib.Path(d.name, "scratch")
        scratch.mkdir()
        paths = frozenset(e["path"] for e in bad)
        out = run_loop(model, str(snap), Allowlist(frozenset(), paths, frozenset()), lambda w, n: BuildResult(ok=True), str(scratch))
        self.assertTrue(out.ok)
        self.assertEqual(len(out.attempts), 2)
        self.assertIn("nginx/nginx.conf: proxy_ssl_verify off (before 0, after 1)", model.calls[1][1])


if __name__ == "__main__":
    unittest.main()
