"""Web UI and API for finished runs: job timeline, CBOM before and after, containment, receipt.

    python3 -m pqproof web --runs DIR [--host 127.0.0.1] [--port 8080]

Standard library only (http.server); the page is static HTML, CSS and plain JavaScript from
pqproof/static, with no build step and nothing from another origin. The server reads run
directories under --runs (what e2e/orders_edge.py --out writes: receipt/receipt.json and its
artifacts) and never runs anything itself. Every run it shows is re-checked on each request with
receipt.verify(), and the page says whether all hashes matched.

    GET  /                               the page (static/index.html, app.js, app.css)
    GET  /api/runs                       runs with a receipt, newest first
    GET  /api/runs/ID                    one run: its receipt.json and the verification result
    GET  /api/runs/ID/replay             the run's recorded events in time order, for the replay
    GET  /runs/ID/receipt/PATH           receipt.html, receipt.json or a file under artifacts/
    POST /api/runs  {"repo": "..."}      ask for a live run: the gate decides

The replay is built from the stored receipt alone: opening it starts nothing, calls no model and
needs no network.

Live runs go through a Gate. The public demo's limits (only allowlisted repositories, one run at a
time, a daily count per IP, a daily inference budget; DESIGN 3-1, commit C20) plug in there, and a
starter(repo, ip, done) function runs an admitted job, returns its run id and calls done() when the
job ends (done releases the gate). The default gate refuses every live run and there is no
starter, so this server only shows recorded runs. It binds 127.0.0.1 unless told otherwise; the client IP a gate sees is
the socket's peer, so a reverse proxy in front must be accounted for when C20 counts per IP.

Slow clients cannot hold it (day-3 review: 1,100 connections that sent a byte every 10 s left it
with 1,021 threads and no answer for anyone): at most MAX_CONNECTIONS are served at once and the
next one gets 503 at once, a client that has not sent its whole request within
REQUEST_DEADLINE_S is dropped, and no connection lasts longer than CONNECTION_DEADLINE_S. Limits
per client (connections and requests per IP) belong to the front end that faces the internet.
A run's verification is kept until a file in its receipt directory changes (size, mtime, ctime,
inode), so repeated requests do not hash the receipt again.
"""
import argparse
import json
import os
import re
import socket
import stat
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from . import receipt

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"),
                "/favicon.svg": ("favicon.svg", "image/svg+xml")}
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}")
MAX_BODY = 4096
MAX_CONNECTIONS = 64  # served at once; the next one gets 503 at once
REQUEST_DEADLINE_S = 10.0  # to send the request line, the headers and the body
CONNECTION_DEADLINE_S = 30.0  # for the whole exchange, a client that reads slowly included
BUSY = (b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\n"
        b"Content-Length: 27\r\nConnection: close\r\nRetry-After: 5\r\n\r\n{\"error\": \"server is busy\"}")
# C0 and C1 control characters, as http.server escapes them in its own log lines (3.12+)
CONTROL = str.maketrans({c: f"\\x{c:02x}" for c in [*range(0x20), *range(0x7f, 0xa0)]})
MAX_REPO = 300
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
RECEIPT_CSP = (f"default-src 'none'; style-src 'unsafe-inline'; script-src {receipt.SCRIPT_CSP}; img-src 'none'; "
               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
FILE_CSP = "default-src 'none'; sandbox; frame-ancestors 'none'"


class Gate:
    """Whether a live run may start. admit(repo, ip) returns None to admit it, or (HTTP status,
    reason) to refuse it; release(repo, ip) is called when an admitted run has ended. This one
    refuses everything: the C20 gate (allowlist, one at a time, per-IP and budget limits) replaces it."""

    def admit(self, repo, ip):
        return HTTPStatus.SERVICE_UNAVAILABLE, "live runs are off: this page shows recorded runs"

    def release(self, repo, ip):
        pass


class WebError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def run_dirs(runs):
    """Run ids under runs that hold receipt/receipt.json (plain directories only, no symlinks)."""
    out = []
    try:
        entries = list(os.scandir(runs))
    except OSError:
        return out
    for entry in entries:
        if RUN_ID.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
            try:
                st = os.lstat(os.path.join(runs, entry.name, "receipt", "receipt.json"))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                out.append(entry.name)
    return out


def load_receipt(runs, run_id):
    if not RUN_ID.fullmatch(run_id or ""):
        raise WebError(HTTPStatus.NOT_FOUND, "no such run")
    try:
        return json.loads(receipt._read_nofollow(runs, f"{run_id}/receipt/receipt.json").decode("utf-8"))
    except (OSError, ValueError):
        raise WebError(HTTPStatus.NOT_FOUND, "no such run") from None


def run_summary(run_id, r):
    model = r.get("model") or {}
    repo = r.get("repo") or {}
    return {"id": run_id, "verdict": r.get("verdict"), "repo": repo.get("url") or repo.get("path"),
            "commit": (r.get("repo") or {}).get("commit"), "started_at": r.get("started_at"),
            "finished_at": r.get("finished_at"), "receipt_id": r.get("receipt_id"),
            "model": ", ".join(model.get("models") or []) or model.get("provider")}


def list_runs(runs, cache=None):
    """Run summaries, newest first, each with whether its receipt passes verify()."""
    out = []
    for run_id in run_dirs(runs):
        try:
            s = run_summary(run_id, load_receipt(runs, run_id))
        except WebError:
            continue
        root = os.path.join(runs, run_id, "receipt")
        s["verified"] = all(ok for ok, _ in (cache.results(root) if cache else receipt.verify(root)))
        out.append(s)
    return sorted(out, key=lambda s: (str(s["started_at"]), s["id"]), reverse=True)


def fingerprint(root):
    """What verify() read, as metadata: every entry under root (not following symlinks)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            out.append((os.path.relpath(os.path.join(dirpath, name), root), st.st_mode, st.st_size, st.st_mtime_ns,
                        st.st_ctime_ns, st.st_ino))
    return tuple(sorted(out))


class VerifyCache:
    """receipt.verify() results by run, kept while the receipt directory's fingerprint holds."""

    def __init__(self, size=256):
        self.size, self.items, self.lock = size, {}, threading.Lock()

    def results(self, root):
        key = fingerprint(root)
        with self.lock:
            hit = self.items.get(root)
        if hit and hit[0] == key:
            return hit[1]
        results = receipt.verify(root)
        if fingerprint(root) == key:  # unchanged while it was read
            with self.lock:
                if len(self.items) >= self.size:
                    self.items.pop(next(iter(self.items)))
                self.items[root] = (key, results)
        return results


def run_detail(runs, run_id, cache=None):
    r = load_receipt(runs, run_id)
    root = os.path.join(runs, run_id, "receipt")
    results = cache.results(root) if cache else receipt.verify(root)
    base = f"/runs/{run_id}/receipt/"
    return {"id": run_id, "receipt": r,
            "verification": {"ok": all(ok for ok, _ in results), "checks": len(results),
                             "failed": [w for ok, w in results if not ok]},
            "links": {"receipt_html": base + "receipt.html", "receipt_json": base + "receipt.json", "base": base}}


def _seconds(iso):
    return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()


def replay(r):
    """The run's recorded events in time order, from its receipt alone: phases, each microVM's start
    and end, every egress attempt that reached the sinkhole (canaries named), refused and passed patch
    attempts, every proof, the verdict. t is seconds after started_at. Proofs and attempts carry no
    time of their own: a proof is placed when its step's microVM was destroyed, an attempt at its
    first microVM, a refused attempt (no microVM: refused before any build) right after the last
    microVM before it."""
    t0 = _seconds(r["started_at"])
    at = lambda iso: round(max(_seconds(iso) - t0, 0.0), 3)  # noqa: E731
    events = []

    def add(t, kind, text, **extra):
        events.append({"t": t, "kind": kind, "text": text, **extra})

    for p in r.get("timeline") or []:
        add(at(p["started_at"]), "phase", p["name"], until=at(p["ended_at"]))
    vms = {}
    for s in r.get("sandboxes") or []:
        step, lim = s.get("step", "?"), s.get("limits") or {}
        start, end = at(s["started_at"]), at(s.get("destroyed_at") or r["finished_at"])
        vms.setdefault(step, (start, end))
        image = str(s.get("image", "")).split("@")[0]
        add(start, "vm", f"microVM for {step}: {image}, {lim.get('cpus')} vCPU, {lim.get('memory_mib')} MiB, "
                         f"{lim.get('wall_clock_s')} s limit, created with --no-net", step=step, until=end)
        for ev in (s.get("egress") or {}).get("reached_sinkhole") or []:
            if ev.get("canaries"):
                add(at(ev["at"]), "exfil", f"EXFIL CAUGHT: {', '.join(ev['canaries'])} sent to {ev.get('dest')} "
                                           f"({ev.get('kind')}, {ev.get('bytes')} bytes) during {step}; it stopped at the sinkhole")
            else:
                add(at(ev["at"]), "egress", f"{step}: {ev.get('kind')} to {ev.get('dest')} reached the sinkhole (recorded)")
        failed = [e for e in s.get("execs") or [] if e.get("exit_code") != 0 and (e.get("argv") or [""])[0] != "tls_probe"]
        what = f"; {' '.join(failed[0]['argv'])} exited {failed[0]['exit_code']}" if failed else ""
        add(end, "vm-failed" if failed else "vm-end",
            f"microVM for {step} destroyed{what}" if s.get("destroyed_at") else f"microVM for {step} not destroyed{what}", step=step)
    def attempt_vms(n):
        return [v for step, v in vms.items() if step in (f"attempt {n} build", f"attempt {n} prove")]

    def before(n):  # the end of the last microVM before attempt n (baseline included)
        ends = [e for step, (_, e) in vms.items() if not step.startswith("attempt ")]
        ends += [e for m in range(1, n) for _, e in attempt_vms(m)]
        return max(ends, default=0.0)

    for a in r.get("attempts") or []:
        n = a.get("number") if isinstance(a.get("number"), int) else 0
        own = attempt_vms(n)
        if a.get("tls_weakening"):
            add(before(n), "refused", f"Patch refused (attempt {n}) before any build: it weakens TLS: "
                                      + "; ".join(a["tls_weakening"]))
        elif own:
            add(min(v[0] for v in own), "attempt-start", f"Attempt {n}: edits applied to a fresh copy, TLS-weakening check passed; build in a new microVM")
            add(max(v[1] for v in own), "attempt", f"Attempt {n}: {a.get('outcome')}", ok=bool(a.get("ok")))
        else:
            add(before(n), "attempt", f"Attempt {n}: {a.get('outcome')}", ok=bool(a.get("ok")))
    for p in r.get("proofs") or []:
        step = p.get("step", "")
        t = (vms.get(f"{step} prove") or vms.get(f"{step} build") or (0.0, at(r["finished_at"])))[1]
        add(t, "proof", f"{step}: {p.get('name')}: expected {p.get('expected')}, got {p.get('actual')}", ok=bool(p.get("ok")))
    verdict = str(r.get("verdict", "")).upper()
    add(at(r["finished_at"]), "verdict", f"Verdict: {verdict}, from the probe's results and exit codes, never from a model")
    # at one instant: a step's proofs, then its outcome, its microVM's end, the next phase, the next microVM
    order = {"proof": 0, "attempt": 1, "vm-end": 2, "vm-failed": 2, "refused": 3, "phase": 4, "attempt-start": 5, "vm": 6,
             "egress": 7, "exfil": 7, "verdict": 8}
    events.sort(key=lambda e: (e["t"], order.get(e["kind"], 9)))
    return {"started_at": r["started_at"], "duration_s": at(r["finished_at"]), "events": events}


def run_replay(runs, run_id, cache=None):
    r = load_receipt(runs, run_id)
    results = cache.results(os.path.join(runs, run_id, "receipt")) if cache else receipt.verify(os.path.join(runs, run_id, "receipt"))
    try:
        out = replay(r)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise WebError(HTTPStatus.UNPROCESSABLE_ENTITY, "this receipt cannot be replayed") from None
    return {"id": run_id, "verified": all(ok for ok, _ in results), **out}


def receipt_file(runs, run_id, rel):
    """(bytes, content type, CSP) of a file in a run's receipt directory, or WebError 404."""
    parts = rel.split("/")
    if not RUN_ID.fullmatch(run_id) or not (rel in ("receipt.html", "receipt.json") or
                                            (parts[0] == "artifacts" and 2 <= len(parts) <= 5)) \
            or not all(SEGMENT.fullmatch(p) for p in parts):
        raise WebError(HTTPStatus.NOT_FOUND, "not found")
    try:
        data = receipt._read_nofollow(runs, f"{run_id}/receipt/{rel}")
    except (OSError, ValueError):
        raise WebError(HTTPStatus.NOT_FOUND, "not found") from None
    if rel == "receipt.html":
        return data, "text/html; charset=utf-8", RECEIPT_CSP
    if rel.endswith(".json"):
        return data, "application/json; charset=utf-8", FILE_CSP
    return data, "text/plain; charset=utf-8", FILE_CSP


class Handler(BaseHTTPRequestHandler):
    server_version = "pq-proof"
    sys_version = ""
    timeout = 10  # one read; the server's deadlines bound the whole request and connection

    def log_message(self, fmt, *args):  # one short line per request, never a body, no control characters
        self.server.log(f"{self.client_address[0]} {fmt % args}".translate(CONTROL))

    def send(self, status, body, ctype, csp=FILE_CSP, head_only=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def json(self, status, value, head_only=False):
        self.send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8",
                  head_only=head_only)

    def route_get(self, head_only=False):
        path = urlsplit(self.path).path
        runs = self.server.runs
        self.server.request_read(self.connection)
        if path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            with open(os.path.join(STATIC, name), "rb") as f:
                return self.send(HTTPStatus.OK, f.read(), ctype, PAGE_CSP, head_only)
        if path == "/api/runs":
            return self.json(HTTPStatus.OK, {"runs": list_runs(runs, self.server.verified), "live_runs": self.server.live_note},
                             head_only)
        m = re.fullmatch(r"/api/runs/([^/]+)", path)
        if m:
            return self.json(HTTPStatus.OK, run_detail(runs, unquote(m[1]), self.server.verified), head_only)
        m = re.fullmatch(r"/api/runs/([^/]+)/replay", path)
        if m:
            return self.json(HTTPStatus.OK, run_replay(runs, unquote(m[1]), self.server.verified), head_only)
        m = re.fullmatch(r"/runs/([^/]+)/receipt/(.+)", path)
        if m:
            data, ctype, csp = receipt_file(runs, unquote(m[1]), unquote(m[2]))
            return self.send(HTTPStatus.OK, data, ctype, csp, head_only)
        raise WebError(HTTPStatus.NOT_FOUND, "not found")

    def handle_one(self, fn):
        try:
            fn()
        except WebError as e:
            self.json(e.status, {"error": str(e)}, head_only=self.command == "HEAD")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa: BLE001 - the client gets no detail, the log gets the type
            self.server.log(f"error: {self.command} {urlsplit(self.path).path}: {type(e).__name__}")
            self.json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    def do_GET(self):
        self.handle_one(self.route_get)

    def do_HEAD(self):
        self.handle_one(lambda: self.route_get(head_only=True))

    def do_POST(self):
        self.handle_one(self.start_run)

    def start_run(self):
        """POST /api/runs: read {"repo"}, ask the gate, hand an admitted run to the starter."""
        if urlsplit(self.path).path != "/api/runs":
            raise WebError(HTTPStatus.NOT_FOUND, "not found")
        length = self.headers.get("Content-Length")
        if length is None or not (length.isascii() and length.isdigit()):
            raise WebError(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")
        if int(length) > MAX_BODY:
            raise WebError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"at most {MAX_BODY} bytes")
        try:
            data = self.rfile.read(int(length))
            self.server.request_read(self.connection)
            body = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise WebError(HTTPStatus.BAD_REQUEST, "body must be JSON") from None
        repo = body.get("repo") if isinstance(body, dict) else None
        if not isinstance(repo, str) or not repo or len(repo) > MAX_REPO or not repo.isprintable():
            raise WebError(HTTPStatus.BAD_REQUEST, f"repo must be one printable line of at most {MAX_REPO} characters")
        ip = self.client_address[0]
        refused = self.server.gate.admit(repo, ip)
        if refused is not None:
            status, reason = refused
            raise WebError(HTTPStatus(status), reason)
        if self.server.starter is None:
            self.server.gate.release(repo, ip)
            raise WebError(HTTPStatus.NOT_IMPLEMENTED, "no live runner in this build")
        try:
            run_id = self.server.starter(repo, ip, lambda: self.server.gate.release(repo, ip))
        except Exception:
            self.server.gate.release(repo, ip)
            raise
        self.json(HTTPStatus.ACCEPTED, {"id": run_id})

    def do_PUT(self):
        self.handle_one(self.not_allowed)

    do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    def not_allowed(self):
        raise WebError(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, runs, gate=None, starter=None, quiet=False):
        super().__init__(addr, Handler)
        self.runs, self.gate, self.starter, self.quiet = os.path.realpath(runs), gate or Gate(), starter, quiet
        self.live_note = "off: recorded runs only" if starter is None else "on, limited"
        self.verified = VerifyCache()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.request_deadline, self.connection_deadline = REQUEST_DEADLINE_S, CONNECTION_DEADLINE_S
        self.deadlines, self.deadlines_lock, self.closed = {}, threading.Lock(), threading.Event()
        self.refused = []  # (close at, socket): a 503 sent, closed a moment later so it is read, not reset
        threading.Thread(target=self._watch, name="pqproof-web-deadlines", daemon=True).start()

    def log(self, line):
        if not self.quiet:
            print(line, flush=True)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self._refuse(request)
            return
        now = time.monotonic()
        with self.deadlines_lock:
            self.deadlines[request] = [now + self.request_deadline, now + self.connection_deadline]
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._done(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._done(request)

    def _done(self, request):
        with self.deadlines_lock:
            self.deadlines.pop(request, None)
        self.slots.release()

    def _refuse(self, request):
        """503 without a thread. The request is drained first and the socket closed a second later
        by the watchdog: closing with unread input would reset the connection before the client
        reads the answer."""
        try:
            request.setblocking(False)
            _drain(request)
            request.send(BUSY)
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        with self.deadlines_lock:
            if len(self.refused) < MAX_CONNECTIONS:
                self.refused.append((time.monotonic() + 1.0, request))
                return
        request.close()

    def request_read(self, request):
        """The client has sent its whole request: only the connection deadline applies now."""
        with self.deadlines_lock:
            if request in self.deadlines:
                self.deadlines[request][0] = float("inf")

    def _watch(self):
        while not self.closed.wait(0.2):
            now = time.monotonic()
            with self.deadlines_lock:
                late = [r for r, (read_by, end_by) in self.deadlines.items() if now > min(read_by, end_by)]
                for r in late:
                    self.deadlines[r] = [float("inf"), float("inf")]  # shut down once
                done = [r for at, r in self.refused if at <= now]
                self.refused = [(at, r) for at, r in self.refused if at > now]
            for r in done:
                _drain(r)
                r.close()
            for r in late:
                try:
                    r.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def server_close(self):
        self.closed.set()
        with self.deadlines_lock:
            refused, self.refused = self.refused, []
        for _, r in refused:
            r.close()
        super().server_close()


def _drain(sock, rounds=16):
    """Read what a non-blocking socket holds now (at most rounds * 64 KiB)."""
    try:
        for _ in range(rounds):
            if not sock.recv(65536):
                return
    except OSError:
        pass


def main(argv):
    ap = argparse.ArgumentParser(prog="python3 -m pqproof web")
    ap.add_argument("--runs", required=True, help="directory of e2e run directories (each with receipt/)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)
    srv = Server((args.host, args.port), args.runs)
    print(f"PQ-Proof web on http://{args.host}:{srv.server_address[1]}/ ({len(run_dirs(srv.runs))} runs in {srv.runs})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
