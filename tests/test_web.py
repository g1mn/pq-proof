"""web: the run viewer's API, its file serving, and the live-run gate (no live runner yet)."""
import http.client
import json
import os
import pathlib
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from unittest import mock

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

    def test_the_run_list_says_which_receipts_fail_their_check(self):
        # day-3 review: a tampered copy was listed as '(pass, ...)' and shown with a green PASS
        _, body = self.get_json("/api/runs")
        self.assertEqual({r["id"]: r["verified"] for r in body["runs"]}, {"e2e-1": True, "e2e-2": False})
        page = (STATIC / "app.js").read_text()
        self.assertIn("UNVERIFIED", page)
        self.assertIn("r.verified ? r.verdict : \"UNVERIFIED\"", page)

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

    def test_replay_opens_from_the_receipt_alone_without_network_or_model(self):
        # C20: no socket to anything but this test's own loopback server, and no inference client
        real_connect = socket.socket.connect

        def loopback_only(sock, address):
            host = address[0] if isinstance(address, tuple) else address
            if sock.family == socket.AF_UNIX or host in ("127.0.0.1", "::1"):
                return real_connect(sock, address)
            raise AssertionError(f"network connection to {address!r} during a replay")

        def no_model(*a, **k):
            raise AssertionError("an inference client was created during a replay")

        real_getaddrinfo = socket.getaddrinfo

        def loopback_names_only(host, *a, **k):
            if host not in ("127.0.0.1", "::1"):
                raise AssertionError(f"DNS lookup of {host!r} during a replay")
            return real_getaddrinfo(host, *a, **k)

        with mock.patch.object(socket.socket, "connect", loopback_only), \
                mock.patch("socket.getaddrinfo", loopback_names_only), \
                mock.patch("pqproof.inference.Client", side_effect=no_model), \
                mock.patch("pqproof.inference.urllib_send", side_effect=no_model):
            for path in ("/", "/app.js", "/app.css", "/api/runs"):
                self.assertEqual(self.req("GET", path)[0], 200, path)
            status, rp = self.get_json("/api/runs/e2e-1/replay")
        self.assertEqual(status, 200)
        self.assertTrue(rp["verified"])
        kinds = [e["kind"] for e in rp["events"]]
        self.assertEqual(kinds[-1], "verdict")
        self.assertEqual([e["t"] for e in rp["events"]], sorted(e["t"] for e in rp["events"]))
        exfil = [e for e in rp["events"] if e["kind"] == "exfil"]
        self.assertTrue(exfil and all("EXFIL CAUGHT" in e["text"] and "CANARY" in e["text"] for e in exfil))
        self.assertEqual(sum(k == "vm" for k in kinds), len(self.receipt["sandboxes"]))
        self.assertEqual(sum(k in ("vm-end", "vm-failed") for k in kinds), len(self.receipt["sandboxes"]))
        self.assertEqual(sum(k == "proof" for k in kinds), len(self.receipt["proofs"]))
        refused = [i for i, e in enumerate(rp["events"]) if e["kind"] == "refused"]
        self.assertEqual(len(refused), 1)  # the fixture's attempt 1 weakens TLS: refused before any build
        self.assertIn("InsecureSkipVerify", rp["events"][refused[0]]["text"])
        self.assertLess(refused[0], next(i for i, e in enumerate(rp["events"]) if e["kind"] == "attempt-start"))
        self.assertEqual(rp["duration_s"], round((web._seconds(self.receipt["finished_at"]) - web._seconds(self.receipt["started_at"])), 3))
        status, rp2 = self.get_json("/api/runs/e2e-2/replay")
        self.assertEqual((status, rp2["verified"]), (200, False))  # a tampered copy replays, marked unverified
        self.assertEqual(self.req("GET", "/api/runs/nope/replay")[0], 404)

    def test_replay_order_of_one_run(self):
        T = lambda s: f"2026-11-04T23:10:{s:06.3f}Z"  # noqa: E731
        vm = lambda step, a, b, execs=(), egress=(): {  # noqa: E731
            "step": step, "started_at": T(a), "destroyed_at": T(b), "image": "golang:1.27@sha256:" + "0" * 64,
            "limits": {"cpus": 2, "memory_mib": 2048, "wall_clock_s": 300}, "execs": list(execs),
            "egress": {"reached_sinkhole": list(egress)}}
        r = {"started_at": T(0), "finished_at": T(50), "verdict": "pass",
             "timeline": [{"name": "plan", "started_at": T(0), "ended_at": T(5)},
                          {"name": "baseline", "started_at": T(5), "ended_at": T(20)},
                          {"name": "patch loop", "started_at": T(20), "ended_at": T(49)}],
             "sandboxes": [vm("baseline build", 5, 12, egress=[{"at": T(9), "canaries": ["CANARY-0001"], "dest": "203.0.113.7:80",
                                                                "kind": "tcp", "bytes": 253}]),
                           vm("baseline prove", 12, 20, execs=[{"argv": ["tls_probe", "hybrid"], "exit_code": 1}]),
                           vm("attempt 2 build", 21, 40), vm("attempt 2 prove", 40, 49)],
             "attempts": [{"number": 1, "tls_weakening": ["InsecureSkipVerify: true"], "outcome": "refused", "ok": False},
                          {"number": 2, "tls_weakening": [], "outcome": "built and proved", "ok": True}],
             "proofs": [{"step": "baseline", "name": "hybrid", "expected": "no connection", "actual": "no connection", "ok": True},
                        {"step": "attempt 2", "name": "hybrid", "expected": "X25519MLKEM768", "actual": "X25519MLKEM768", "ok": True}]}
        got = [(e["t"], e["kind"]) for e in web.replay(r)["events"]]
        self.assertEqual(got, [
            (0.0, "phase"), (5.0, "phase"), (5.0, "vm"), (9.0, "exfil"), (12.0, "vm-end"), (12.0, "vm"),
            (20.0, "proof"), (20.0, "vm-end"),  # an expected tls_probe failure is not a failed microVM
            (20.0, "refused"), (20.0, "phase"), (21.0, "attempt-start"), (21.0, "vm"), (40.0, "vm-end"), (40.0, "vm"),
            (49.0, "proof"), (49.0, "attempt"), (49.0, "vm-end"), (50.0, "verdict")])

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


def raw(port, data, timeout=5):
    """Send bytes as they are, read until the server closes or timeout."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(data)
    out = b""
    try:
        while chunk := s.recv(65536):
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return out


class Abuse(unittest.TestCase):
    """Day-3 review: slow clients, odd request lines and headers, a verification on every request."""

    def serve(self, runs=None):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        srv = web.Server(("127.0.0.1", 0), runs or d.name, quiet=True)
        self.lines = []
        srv.log = self.lines.append
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    def test_slow_clients_cannot_hold_the_server(self):
        # the review held 1,100 connections that sent a byte every 10 s: 1,021 threads, 1,056 open
        # files, and no answer for anyone until they closed
        with mock.patch.object(web, "MAX_CONNECTIONS", 8, create=True), \
                mock.patch.object(web, "REQUEST_DEADLINE_S", 1.0, create=True):
            srv = self.serve()
        port, threads = srv.server_address[1], threading.active_count()
        slow = []
        for _ in range(30):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /api/ru")
            slow.append(s)
        self.addCleanup(lambda: [s.close() for s in slow])
        time.sleep(0.3)
        self.assertLessEqual(threading.active_count() - threads, 8 + 2)  # handler threads are capped
        busy = raw(port, b"GET /api/runs HTTP/1.0\r\n\r\n").split(b"\r\n", 1)[0]
        self.assertIn(busy, (b"HTTP/1.0 503 Service Unavailable", b"HTTP/1.0 200 OK"))  # an answer, at once
        time.sleep(1.8)  # past the deadline for sending a request: the slow ones are dropped
        for s in slow[:8]:
            s.settimeout(2)
            try:
                rest = s.recv(100)
            except OSError:
                rest = b""
            self.assertNotIn(b"200", rest)
        self.assertEqual(raw(port, b"GET /api/runs HTTP/1.0\r\n\r\n").split(b"\r\n", 1)[0], b"HTTP/1.0 200 OK")

    def test_log_lines_carry_no_control_characters(self):
        srv = self.serve()
        raw(srv.server_address[1], b"GET /\x1b]0;owned\x07\x1b[2J\rFAKE 200 HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.2)
        self.assertTrue(self.lines)
        self.assertEqual([ln for ln in self.lines if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in ln)], [])

    def test_an_odd_content_length_is_a_client_error(self):
        srv = self.serve()
        for value in (b"\xb2", "\u0663".encode(), b"-1", b"1e3"):  # superscript two, Arabic-Indic three
            with self.subTest(value=value):
                head = raw(srv.server_address[1], b"POST /api/runs HTTP/1.1\r\nHost: x\r\nContent-Length: " + value
                           + b"\r\n\r\n{}").split(b"\r\n", 1)[0]
                self.assertEqual(head, b"HTTP/1.0 411 Length Required")

    def test_a_receipt_is_verified_again_only_when_its_files_change(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        report, log_dir = make_run(d.name)
        runs = os.path.join(d.name, "runs")
        r = receipt.build(report, log_dir, os.path.join(runs, "e2e-1", "receipt"))
        srv = self.serve(runs)
        calls = []
        real = receipt.verify

        def counted(root):
            calls.append(root)
            return real(root)

        def check():
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            c.request("GET", "/api/runs/e2e-1")
            out = json.loads(c.getresponse().read())["verification"]["ok"]
            c.close()
            return out
        with mock.patch.object(receipt, "verify", counted):
            self.assertEqual([check(), check(), check()], [True, True, True])
            self.assertEqual(len(calls), 1)
            pathlib.Path(runs, "e2e-1", "receipt", r["proofs"][0]["log"]).write_text("forged\n")
            self.assertFalse(check())
            self.assertEqual(len(calls), 2)


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
