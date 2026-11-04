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
    GET  /runs/ID/receipt/PATH           receipt.html, receipt.json or a file under artifacts/
    POST /api/runs  {"repo": "..."}      ask for a live run: the gate decides

Live runs go through a Gate. The public demo's limits (only allowlisted repositories, one run at a
time, a daily count per IP, a daily inference budget; DESIGN 3-1, commit C20) plug in there, and a
starter(repo, ip, done) function runs an admitted job, returns its run id and calls done() when the
job ends (done releases the gate). The default gate refuses every live run and there is no
starter, so this server only shows recorded runs. It binds 127.0.0.1 unless told otherwise; the client IP a gate sees is
the socket's peer, so a reverse proxy in front must be accounted for when C20 counts per IP.
"""
import argparse
import json
import os
import re
import stat
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
    return {"id": run_id, "verdict": r.get("verdict"), "repo": (r.get("repo") or {}).get("url"),
            "commit": (r.get("repo") or {}).get("commit"), "started_at": r.get("started_at"),
            "finished_at": r.get("finished_at"), "receipt_id": r.get("receipt_id"),
            "model": ", ".join(model.get("models") or []) or model.get("provider")}


def list_runs(runs):
    out = []
    for run_id in run_dirs(runs):
        try:
            out.append(run_summary(run_id, load_receipt(runs, run_id)))
        except WebError:
            continue
    return sorted(out, key=lambda s: (str(s["started_at"]), s["id"]), reverse=True)


def run_detail(runs, run_id):
    r = load_receipt(runs, run_id)
    results = receipt.verify(os.path.join(runs, run_id, "receipt"))
    base = f"/runs/{run_id}/receipt/"
    return {"id": run_id, "receipt": r,
            "verification": {"ok": all(ok for ok, _ in results), "checks": len(results),
                             "failed": [w for ok, w in results if not ok]},
            "links": {"receipt_html": base + "receipt.html", "receipt_json": base + "receipt.json", "base": base}}


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
    timeout = 15  # a client that sends nothing is dropped

    def log_message(self, fmt, *args):  # one short line per request, never a body
        self.server.log(f"{self.client_address[0]} {fmt % args}")

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
        if path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            with open(os.path.join(STATIC, name), "rb") as f:
                return self.send(HTTPStatus.OK, f.read(), ctype, PAGE_CSP, head_only)
        if path == "/api/runs":
            return self.json(HTTPStatus.OK, {"runs": list_runs(runs), "live_runs": self.server.live_note}, head_only)
        m = re.fullmatch(r"/api/runs/([^/]+)", path)
        if m:
            return self.json(HTTPStatus.OK, run_detail(runs, unquote(m[1])), head_only)
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
        if length is None or not length.isdigit():
            raise WebError(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")
        if int(length) > MAX_BODY:
            raise WebError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"at most {MAX_BODY} bytes")
        try:
            body = json.loads(self.rfile.read(int(length)).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
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

    def log(self, line):
        if not self.quiet:
            print(line, flush=True)


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
