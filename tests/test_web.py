"""web: the run viewer's API, its file serving, and the live-run gate (no live runner yet)."""
import http.client
import json
import os
import pathlib
import re
import shutil
import tempfile
import threading
import unittest
from http import HTTPStatus

from pqproof import receipt, web
from test_receipt import make_run

STATIC = pathlib.Path(web.STATIC)


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        report, log_dir = make_run(cls.tmp.name)
        cls.runs = os.path.join(cls.tmp.name, "runs")
        cls.receipt = receipt.build(report, log_dir, os.path.join(cls.runs, "e2e-1", "receipt"))
        # a second run whose receipt was tampered with after the fact, and things that are not runs
        shutil.copytree(os.path.join(cls.runs, "e2e-1"), os.path.join(cls.runs, "e2e-2"))
        pathlib.Path(cls.runs, "e2e-2", "receipt", cls.receipt["proofs"][0]["log"]).write_text("forged\n")
        os.makedirs(os.path.join(cls.runs, "empty"))
        os.symlink(os.path.join(cls.runs, "e2e-1"), os.path.join(cls.runs, "linked"))
        pathlib.Path(cls.tmp.name, "secret.txt").write_text("outside the runs directory\n")
        cls.start(cls)

    def start(self, gate=None, starter=None):
        self.srv = web.Server(("127.0.0.1", 0), self.runs, gate, starter, quiet=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, headers=None, srv=None):
        c = http.client.HTTPConnection("127.0.0.1", (srv or self.srv).server_address[1], timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def get_json(self, path):
        status, headers, data = self.req("GET", path)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        return status, json.loads(data)

    def test_runs_list_only_real_run_directories(self):
        status, body = self.get_json("/api/runs")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["id"] for r in body["runs"]), ["e2e-1", "e2e-2"])  # not "empty", not the symlink
        run = next(r for r in body["runs"] if r["id"] == "e2e-1")
        self.assertEqual((run["verdict"], run["receipt_id"]), ("pass", self.receipt["receipt_id"]))
        self.assertEqual(body["live_runs"], "off: recorded runs only")

    def test_a_run_comes_with_its_receipt_and_a_fresh_hash_check(self):
        status, body = self.get_json("/api/runs/e2e-1")
        self.assertEqual(status, 200)
        self.assertEqual(body["receipt"], self.receipt)
        self.assertEqual(body["verification"]["failed"], [])
        self.assertTrue(body["verification"]["ok"])
        self.assertEqual(body["links"]["receipt_html"], "/runs/e2e-1/receipt/receipt.html")
        status, body = self.get_json("/api/runs/e2e-2")  # tampered: still shown, flagged
        self.assertFalse(body["verification"]["ok"])
        self.assertTrue(any(self.receipt["proofs"][0]["log"] in f for f in body["verification"]["failed"]))

    def test_receipt_files_are_served_with_a_strict_policy(self):
        status, headers, data = self.req("GET", "/runs/e2e-1/receipt/receipt.html")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(receipt.SCRIPT_CSP, headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        log = self.receipt["proofs"][0]["log"]
        status, headers, data = self.req("GET", f"/runs/e2e-1/receipt/{log}")
        self.assertEqual((status, headers["Content-Type"]), (200, "text/plain; charset=utf-8"))
        self.assertIn("sandbox", headers["Content-Security-Policy"])
        self.assertEqual(data, pathlib.Path(self.runs, "e2e-1", "receipt", log).read_bytes())
        status, headers, _ = self.req("HEAD", "/runs/e2e-1/receipt/receipt.json")
        self.assertEqual((status, headers["Content-Type"]), (200, "application/json; charset=utf-8"))

    def test_nothing_outside_a_receipt_is_served(self):
        for path in ("/runs/e2e-1/receipt/../../../secret.txt", "/runs/e2e-1/receipt/%2e%2e/%2e%2e/%2e%2e/secret.txt",
                     "/runs/..%2f..%2fsecret.txt/receipt/receipt.json", "/runs/e2e-1/receipt/artifacts/../receipt.json",
                     "/runs/linked/receipt/receipt.json", "/runs/e2e-1/../e2e-1/receipt/receipt.json",
                     "/runs/e2e-1/report.json", "/runs/e2e-1/receipt/artifacts", "/runs/e2e-1/receipt/.hidden",
                     "/api/runs/..", "/api/runs/linked", "/api/runs/empty", "/static/app.js", "/etc/passwd"):
            with self.subTest(path):
                status, _, data = self.req("GET", path)
                self.assertEqual(status, 404, data[:200])
                self.assertNotIn(b"outside the runs directory", data)

    def test_a_symlink_inside_a_receipt_is_not_followed(self):
        art = pathlib.Path(self.runs, "e2e-1", "receipt", "artifacts", "link.txt")
        art.symlink_to(pathlib.Path(self.tmp.name, "secret.txt"))
        self.addCleanup(art.unlink)
        status, _, data = self.req("GET", "/runs/e2e-1/receipt/artifacts/link.txt")
        self.assertEqual(status, 404)
        self.assertNotIn(b"outside", data)

    def test_the_page_loads_nothing_from_another_origin(self):
        status, headers, data = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
        for name in ("index.html", "app.js", "app.css", "favicon.svg"):
            text = (STATIC / name).read_text().replace('xmlns="http://www.w3.org/2000/svg"', "")  # a namespace, not a fetch
            self.assertNotRegex(text, r"(?i)https?://|//[a-z0-9-]+\.[a-z]|@import|<iframe|\bimport\s*\(", name)
            self.assertNotIn("signed", text.lower(), name)
        page = (STATIC / "index.html").read_text()
        self.assertEqual(sorted(re.findall(r'(?:src|href)="([^"]+)"', page)), ["/app.css", "/app.js", "/favicon.svg"])
        self.assertNotIn("innerHTML", (STATIC / "app.js").read_text())  # receipt text only ever goes in as text
        for path, ctype in (("/app.js", "text/javascript; charset=utf-8"), ("/app.css", "text/css; charset=utf-8")):
            status, headers, _ = self.req("GET", path)
            self.assertEqual((status, headers["Content-Type"]), (200, ctype))

    def test_live_runs_are_refused_by_the_default_gate(self):
        status, _, data = self.req("POST", "/api/runs", body=json.dumps({"repo": "https://github.com/g1mn/orders-edge"}),
                                   headers={"Content-Type": "application/json"})
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertIn("live runs are off", json.loads(data)["error"])

    def test_bad_requests(self):
        cases = [("POST", "/api/runs", b"{", 400), ("POST", "/api/runs", json.dumps({"repo": 7}).encode(), 400),
                 ("POST", "/api/runs", json.dumps({"repo": "a\nb"}).encode(), 400),
                 ("POST", "/api/runs", json.dumps({"repo": "x" * 5000}).encode(), 413),
                 ("POST", "/api/other", b"{}", 404), ("PUT", "/api/runs", b"{}", 405), ("DELETE", "/api/runs/e2e-1", None, 405)]
        for method, path, body, want in cases:
            with self.subTest(method=method, path=path, want=want):
                status, _, _ = self.req(method, path, body=body)
                self.assertEqual(status, want)
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=10)
        c.putrequest("POST", "/api/runs")
        c.endheaders()
        self.assertEqual(c.getresponse().status, HTTPStatus.LENGTH_REQUIRED)
        c.close()


class LiveGate(unittest.TestCase):
    """The hook C20's limits plug into: a gate that admits or refuses, and a starter for admitted runs."""

    def serve(self, gate, starter):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        srv = web.Server(("127.0.0.1", 0), d.name, gate, starter, quiet=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    def post(self, srv, repo):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        c.request("POST", "/api/runs", body=json.dumps({"repo": repo}))
        r = c.getresponse()
        out = r.status, json.loads(r.read())
        c.close()
        return out

    def test_the_gate_sees_repo_and_ip_and_its_reason_reaches_the_client(self):
        class OneAtATime(web.Gate):
            def __init__(self):
                self.calls, self.busy, self.released = [], False, []

            def admit(self, repo, ip):
                self.calls.append((repo, ip))
                if repo != "orders-edge":
                    return 403, "only allowlisted fixtures"
                if self.busy:
                    return 429, "one live run at a time"
                self.busy = True
                return None

            def release(self, repo, ip):
                self.busy = False
                self.released.append(repo)

        gate, started = OneAtATime(), []
        srv = self.serve(gate, lambda repo, ip, done: started.append(done) or f"live-{len(started)}")
        self.assertEqual(self.post(srv, "https://example.invalid/x"), (403, {"error": "only allowlisted fixtures"}))
        self.assertEqual(self.post(srv, "orders-edge"), (202, {"id": "live-1"}))
        self.assertEqual(self.post(srv, "orders-edge"), (429, {"error": "one live run at a time"}))
        started[0]()  # the run ends: the gate is released
        self.assertEqual(gate.released, ["orders-edge"])
        self.assertEqual(self.post(srv, "orders-edge"), (202, {"id": "live-2"}))
        self.assertEqual(gate.calls[0], ("https://example.invalid/x", "127.0.0.1"))

    def test_an_admitted_run_without_a_runner_or_with_a_failing_one_releases_the_gate(self):
        class Admit(web.Gate):
            released = 0

            def admit(self, repo, ip):
                return None

            def release(self, repo, ip):
                Admit.released += 1

        srv = self.serve(Admit(), None)
        self.assertEqual(self.post(srv, "orders-edge")[0], 501)

        def broken(repo, ip, done):
            raise RuntimeError("runner crashed")

        srv = self.serve(Admit(), broken)
        status, body = self.post(srv, "orders-edge")
        self.assertEqual((status, body), (500, {"error": "internal error"}))
        self.assertEqual(Admit.released, 2)


if __name__ == "__main__":
    unittest.main()
