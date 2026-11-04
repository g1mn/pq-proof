"""Hashed receipt of one run: receipt.json, receipt.html and the files they name.

A run's report (e2e/orders_edge.py) and the command logs its microVM steps wrote become a receipt
directory:

    receipt.json        what was proved, by which commands, in which microVMs, with which egress
    receipt.html        the same receipt as a page (no external resources, dark or light)
    artifacts/          plan, CBOM before and after, each attempt's diff and error, every
                        command's log, the host's command lines, the model's request ledger

receipt.json lists every artifact with its byte count and SHA-256, and every field that points at
a file (log, diff, file) has a matching *_sha256 field. receipt_id is the SHA-256 of receipt.json
itself without that field (keys sorted, no whitespace, UTF-8), so one hash covers the whole
receipt and, through the manifest, every artifact. `python3 -m pqproof verify-receipt DIR`
recomputes all of it, checks receipt.json against SCHEMA, and renders receipt.html again to
compare it with the file.

This is a hashed receipt, not proof of who wrote it: anyone can change a file and write new
hashes. The id is worth something only when it is compared with an id taken from a source the
reader trusts (the run's own output, the object store it was uploaded to). The receipt never calls
itself anything more than that.
"""
import base64
import hashlib
import html
import json
import os
import re
import stat
import time

from . import prove
from .loop import _open_nofollow
from .plan import clean_text

FORMAT = "pq-proof hashed receipt 1"
NOTE = ("Hashed receipt: receipt_id is the SHA-256 of this JSON without receipt_id (sorted keys, no whitespace, "
        "UTF-8), and every file in artifacts is listed with its SHA-256. `python3 -m pqproof verify-receipt DIR` "
        "recomputes them. The hashes show that the files are the ones this receipt names; they do not show who "
        "produced it, so compare receipt_id with one from a source you trust.")
MAX_ARTIFACT = 64 << 20
MAX_PREVIEW = 200
POLICY = ["every microVM: msb create --no-net (all traffic denied, the host and private ranges included)",
          "DNS: only to the host sinkhole's resolver, which records each query and answers NXDOMAIN",
          "TCP: only to 203.0.113.0/24 (RFC 5737, never routed), through the sinkhole proxy, which records it",
          "everything else, the internet, the host and the cloud metadata address included, is dropped by "
          "Microsandbox before it reaches the sinkhole: blocked, not counted"]
DROPPED = "not counted"
REL_LOG = re.compile(r"[A-Za-z0-9_.-]{1,120}/[0-9]{2,4}-[A-Za-z0-9_.-]{1,40}\.log")
ARTIFACT_PATH = re.compile(r"artifacts/[A-Za-z0-9_.-]{1,120}(?:/[A-Za-z0-9_.-]{1,120}){0,3}")

# ---------------------------------------------------------------------------------------------
# Schema: the JSON Schema subset validate() understands (type, const, enum, pattern, minimum,
# required, properties, additionalProperties, items, minItems).
SHA = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
SHA_OR_NULL = {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"}
TIME = {"type": "string", "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"}
TIME_OR_NULL = dict(TIME, type=["string", "null"])
PATH = {"type": "string", "pattern": "^" + ARTIFACT_PATH.pattern + "$"}
PATH_OR_NULL = dict(PATH, type=["string", "null"])
STR, INT, BOOL = {"type": "string"}, {"type": "integer", "minimum": 0}, {"type": "boolean"}
INT_OR_NULL = {"type": ["integer", "null"]}
STRS = {"type": "array", "items": STR}


def obj(required, **props):
    """An object schema with exactly these properties; all of them required unless listed otherwise."""
    return {"type": "object", "additionalProperties": False, "required": sorted(required), "properties": props}


def strict(**props):
    return obj(props, **props)


ROW = strict(path=STR, line=INT, component=STR, kind=STR, algorithm=STR, detail=STR, nist=STR,
             blocks_hybrid={"type": ["boolean", "null"]}, auto_fix=BOOL)
STREAM = strict(bytes=INT, sha256=SHA)
EXEC = strict(argv=STRS, exit_code=INT_OR_NULL, timed_out=BOOL, stdout=STREAM, stderr=STREAM, log=PATH, log_sha256=SHA)
EVENT = strict(kind={"enum": ["tcp", "dns"]}, proto=STR, dest=STR, bytes=INT, sha256=SHA, canaries=STRS, preview=STR,
               at=TIME)
SANDBOX = strict(id=STR, step=STR, image=STR, image_digest=STR, platform_digest={"type": ["string", "null"]},
                 architecture={"type": ["string", "null"]},
                 limits=strict(cpus=INT, memory_mib=INT, wall_clock_s=INT), started_at=TIME, destroyed_at=TIME_OR_NULL,
                 network=STRS, msb_commands=INT, execs={"type": "array", "items": EXEC},
                 egress=strict(reached_sinkhole={"type": "array", "items": EVENT}, reached_sinkhole_not_kept=INT,
                               dropped_by_policy={"const": DROPPED}))
SCHEMA = strict(
    format={"const": FORMAT}, receipt_id=SHA, note={"const": NOTE}, verdict={"enum": ["pass", "fail"]},
    repo=strict(url=STR, commit={"type": "string", "pattern": "^[0-9a-f]{40}$"}),
    started_at=TIME, finished_at=TIME, destroyed_at=TIME_OR_NULL,
    checks={"type": "object", "additionalProperties": {"type": ["boolean", "integer", "array", "null"]}},
    timeline={"type": "array", "items": strict(name=STR, started_at=TIME, ended_at=TIME)},
    sandboxes={"type": "array", "minItems": 1, "items": SANDBOX},
    probe=strict(name=STR, version=STR, sha256=SHA, source_sha256=SHA, built_with=STR),
    plan=strict(file=PATH, file_sha256=SHA, commands={"type": "array", "items": STRS},
                images={"type": "array", "items": strict(requested=STR, pinned=STR, digest=STR, architecture=STR)},
                targets={"type": "array", "items": strict(addr=STR, server=STR)}),
    cbom=strict(before={"type": "array", "items": ROW}, after={"type": ["array", "null"], "items": ROW},
                before_file=PATH, before_file_sha256=SHA, after_file=PATH_OR_NULL, after_file_sha256=SHA_OR_NULL),
    patch={"type": ["object", "null"], "additionalProperties": False, "required": ["attempt", "diff", "diff_sha256", "files"],
           "properties": {"attempt": INT, "diff": PATH, "diff_sha256": SHA, "files": STRS}},
    attempts={"type": "array", "items": strict(number=INT, ok=BOOL, outcome=STR, diff=PATH_OR_NULL, diff_sha256=SHA_OR_NULL,
                                               error=PATH_OR_NULL, error_sha256=SHA_OR_NULL, tls_weakening=STRS)},
    proofs={"type": "array", "items": strict(name=STR, step=STR, command=STRS, expected=STR, actual=STR,
                                             exit_code=INT_OR_NULL, ok=BOOL, log=PATH, log_sha256=SHA)},
    not_fixed={"type": "array", "items": strict(item=STR, reason=STR)},
    containment=strict(policy=STRS, canaries_caught=STRS, reached_sinkhole=INT, reached_sinkhole_not_kept=INT,
                       dropped_by_policy={"const": DROPPED}, host_build_commands=INT, guest_build_commands=INT,
                       sandboxes=INT, sandboxes_destroyed=INT, tls_weakening_refused={"type": "array", "items": INT}),
    model=strict(provider=STR, models=STRS, params={"type": ["object", "null"]}, tokens={"type": ["object", "null"]},
                 requests_sent=INT_OR_NULL, requests_without_usage=INT_OR_NULL,
                 cost_usd={"type": ["number", "null"]}, requests=PATH_OR_NULL, requests_sha256=SHA_OR_NULL),
    host_commands=strict(file=PATH, file_sha256=SHA, count=INT),
    artifacts={"type": "array", "minItems": 1, "items": strict(path=PATH, bytes=INT, sha256=SHA)},
)

TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict,
         "null": type(None)}


def _is(value, name):
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, TYPES[name])


def validate(value, schema, where="receipt"):
    """Every way value breaks schema, as "where: problem" lines ([] when it fits)."""
    out = []
    if "const" in schema and value != schema["const"]:
        return [f"{where}: must be {schema['const']!r}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: must be one of {schema['enum']}"]
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is(value, n) for n in names):
            return [f"{where}: must be {' or '.join(names)}, not {type(value).__name__}"]
    if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value):
        out.append(f"{where}: does not match {schema['pattern']}")
    if _is(value, "number") and "minimum" in schema and value < schema["minimum"]:
        out.append(f"{where}: below {schema['minimum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(f"{where}: needs at least {schema['minItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                out += validate(item, schema["items"], f"{where}[{i}]")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                out.append(f"{where}: missing {key}")
        props, extra = schema.get("properties", {}), schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                out += validate(item, props[key], f"{where}.{key}")
            elif extra is False:
                out.append(f"{where}: unexpected field {key}")
            elif isinstance(extra, dict):
                out += validate(item, extra, f"{where}.{key}")
    return out


# ---------------------------------------------------------------------------------------------
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_id(receipt):
    return hashlib.sha256(canonical({k: v for k, v in receipt.items() if k != "receipt_id"})).hexdigest()


def iso(t):
    """UTC time with milliseconds, as the schema wants it (None stays None)."""
    if t is None:
        return None
    ms = int(float(t) * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + f".{ms % 1000:03d}Z"


class _Artifacts:
    """Writes files under out/artifacts and keeps the manifest."""

    def __init__(self, out):
        self.out, self.items = out, {}

    def add(self, rel, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        path = "artifacts/" + rel
        if not ARTIFACT_PATH.fullmatch(path) or ".." in path.split("/"):
            raise ValueError(f"bad artifact path {path!r}")
        if path in self.items:
            return path, self.items[path]["sha256"]
        full = os.path.join(self.out, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "xb") as f:
            f.write(data)
        digest = hashlib.sha256(data).hexdigest()
        self.items[path] = {"path": path, "bytes": len(data), "sha256": digest}
        return path, digest

    def add_json(self, rel, value):
        return self.add(rel, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    def add_log(self, log_dir, rel):
        """A command log the pipeline wrote (pipeline.write_exec_log), read without following links."""
        if not REL_LOG.fullmatch(rel):
            raise ValueError(f"bad log path {rel!r}")
        return self.add("logs/" + rel, _read_nofollow(log_dir, rel))


def _read_nofollow(root, rel, limit=MAX_ARTIFACT):
    fd = _open_nofollow(os.path.realpath(root), rel, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{rel} is not a regular file")
        if st.st_size > limit:
            raise ValueError(f"{rel} is larger than {limit} bytes")
        return f.read(limit + 1)


def _steps(report):
    """(step label, session record) for every microVM of the run, in order."""
    out = []
    if report.get("probe_build"):
        out.append(("probe build", report["probe_build"]))
    for label, detail in [("baseline", (report.get("baseline") or {}).get("detail") or {})] + \
            [(f"attempt {a['number']}", a.get("detail") or {}) for a in report.get("attempts", [])]:
        for kind in ("build", "prove"):
            if kind in detail:
                out.append((f"{label} {kind}", detail[kind]))
    return out


def _network(host_commands):
    """The network flags of the session's `msb create` line (what egress.Sinkhole.msb_args gave)."""
    for argv in host_commands:
        if len(argv) > 1 and argv[1] == "create" and "--" in argv:
            args = argv[:argv.index("--")]
            out, i = [], 0
            while i < len(args):
                if args[i] in ("--no-net",):
                    out.append(args[i])
                elif args[i] in ("--net-rule", "--dns-nameserver", "--proxy", "--max-tcp-connections", "--net-egress-ops"):
                    out.append(f"{args[i]} {args[i + 1] if i + 1 < len(args) else ''}".strip())
                    i += 1
                i += 1
            return out
    return []


def _sandbox(step, rec, images, art, log_dir):
    image = rec["image"]
    resolved = next((i for i in images if image in (i.get("pinned"), i.get("requested"))), None)
    execs = []
    for e in rec.get("execs", []):
        log, log_sha = art.add_log(log_dir, e["log"])
        execs.append({"argv": [str(a) for a in e["argv"]], "exit_code": e["exit_code"], "timed_out": bool(e["timed_out"]),
                      "stdout": e["stdout"], "stderr": e["stderr"], "log": log, "log_sha256": log_sha})
    events = [{"kind": ev["kind"], "proto": ev["proto"], "dest": clean_text(ev["dest"], MAX_PREVIEW),
               "bytes": ev["bytes"], "sha256": ev["sha256"], "canaries": list(ev["canaries"]),
               "preview": clean_text(str(ev.get("preview", "")).replace("\r\n", "\n"))[:MAX_PREVIEW], "at": iso(ev["t"])}
              for ev in rec["egress"]["sinkhole_events"]]
    return {"id": rec["sandbox"], "step": step, "image": image, "image_digest": image.rpartition("@")[2],
            "platform_digest": resolved["digest"] if resolved else None,
            "architecture": resolved["architecture"] if resolved else None,
            "limits": {k: rec["limits"][k] for k in ("cpus", "memory_mib", "wall_clock_s")},
            "started_at": iso(rec["started_at"]), "destroyed_at": iso(rec["destroyed_at"]),
            "network": _network(rec.get("host_commands", [])), "msb_commands": len(rec.get("host_commands", [])),
            "execs": execs,
            "egress": {"reached_sinkhole": events, "reached_sinkhole_not_kept": rec["egress"].get("uncounted", 0),
                       "dropped_by_policy": DROPPED}}


def _handshake_text(hs):
    if not hs:
        return "not run"
    if hs.get("kind") == "failed":
        return f"no connection ({hs.get('error') or 'handshake failed'})"
    return f"{hs.get('group') or 'unknown group'} ({hs.get('kind')})"


def _proofs(step, detail, servers, final, sandbox):
    """Proofs from one build-and-prove step: tests, nginx -t, both probe controls, each target twice."""
    verdict = detail.get("verdict") or {}
    out = []

    def add(name, e, expected, actual, ok):
        out.append({"name": name, "step": step, "command": e["argv"], "expected": expected, "actual": actual,
                    "exit_code": e["exit_code"], "ok": bool(ok), "log": e["log"], "log_sha256": e["log_sha256"]})

    build, prove_ = sandbox.get("build"), sandbox.get("prove")
    for e in build["execs"] if build else []:
        if e["argv"][:1] == ["make"] or e["argv"][:2] in (["go", "test"], ["go", "vet"]):
            add(f"repository tests: {' '.join(e['argv'])}", e, "exit code 0", f"exit code {e['exit_code']}", e["exit_code"] == 0)
    for e in prove_["execs"] if prove_ else []:
        argv = e["argv"]
        if argv[:2] == ["nginx", "-t"]:
            add("nginx configuration test", e, "exit code 0", f"exit code {e['exit_code']}", e["exit_code"] == 0)
            continue
        if argv[:2] != [prove.PROBE_NAME, "connect"]:
            continue
        addr = argv[-1]
        groups = next((a[len("-groups="):] for a in argv if a.startswith("-groups=")), "")
        hybrid_client = groups == prove.OFFER_HYBRID
        client = "hybrid-only client" if hybrid_client else "classical client"
        if addr == prove.CONTROL_ADDR:
            hs = verdict.get("positive_control")
            add("positive control: hybrid-only client to the probe's hybrid reference server", e,
                prove.OFFER_HYBRID, _handshake_text(hs), (hs or {}).get("group") == prove.OFFER_HYBRID)
        elif addr == prove.NEGATIVE_ADDR:
            hs = ((verdict.get("negative_control") or {}).get("hybrid" if hybrid_client else "classical"))
            if hybrid_client:
                add(f"negative control: {client} to the X25519-only reference server", e, "no connection",
                    _handshake_text(hs), (hs or {}).get("kind") == "failed")
            else:
                add(f"negative control: {client} to the X25519-only reference server", e, prove.NEGATIVE_GROUPS,
                    _handshake_text(hs), (hs or {}).get("group") == prove.NEGATIVE_GROUPS)
        else:
            hs = ((verdict.get("targets") or {}).get(addr) or {}).get("hybrid" if hybrid_client else "classical")
            name = f"{addr} ({servers.get(addr, '?')}): {client}"
            if hybrid_client:
                want = prove.OFFER_HYBRID if final else "no connection (classical-only server)"
                ok = (hs or {}).get("group") == prove.OFFER_HYBRID if final else (hs or {}).get("kind") == "failed"
            else:
                want = "a classical group (older clients still connect)"
                ok = (hs or {}).get("kind") == "classical" if final else (hs or {}).get("kind") in ("classical", "hybrid")
            add(name, e, want, _handshake_text(hs), ok)
    return out


def build(report, log_dir, out):
    """Write the receipt directory for a finished run (report as e2e/orders_edge.py writes it) and
    return receipt.json's content. out must not exist yet."""
    os.makedirs(out)
    art = _Artifacts(out)
    images = report.get("images") or []
    servers = {t["addr"]: t["server"] for t in report["plan"]["targets"]}
    sandboxes, by_detail = [], {}
    for step, rec in _steps(report):
        sb = _sandbox(step, rec, images, art, log_dir)
        sandboxes.append(sb)
        by_detail[id(rec)] = sb

    def sessions(detail):
        return {k: by_detail[id(detail[k])] for k in ("build", "prove") if k in detail}

    plan_file, plan_sha = art.add_json("plan.json", report["plan"])
    before_file, before_sha = art.add_json("cbom-before.json", report["cbom_before"])
    after = report.get("cbom_after")
    after_file, after_sha = art.add_json("cbom-after.json", after) if after is not None else (None, None)

    attempts, patch = [], None
    for a in report.get("attempts", []):
        diff, diff_sha = art.add(f"attempt-{a['number']}.diff", a["diff"]) if a.get("diff") else (None, None)
        err, err_sha = art.add(f"attempt-{a['number']}.error.txt", a["raw_error"]) if a.get("raw_error") else (None, None)
        weak = []
        if str(a.get("raw_error", "")).startswith("edit refused: the patch weakens TLS"):
            weak = [clean_text(line, 300) for line in a["raw_error"].splitlines()[1:] if line.strip()]
            outcome = "refused before any build: the patch weakens TLS"
        elif str(a.get("raw_error", "")).startswith("edit refused"):
            outcome = "refused before any build: an edit did not apply"
        elif a.get("ok"):
            outcome = "built and proved"
        else:
            outcome = "build or proof failed; the raw output went back to the model"
        attempts.append({"number": a["number"], "ok": bool(a.get("ok")), "outcome": outcome, "diff": diff,
                         "diff_sha256": diff_sha, "error": err, "error_sha256": err_sha, "tls_weakening": weak})
        if a.get("ok") and diff:
            files = sorted({ln[6:] for ln in a["diff"].splitlines() if ln.startswith("+++ b/")})
            patch = {"attempt": a["number"], "diff": diff, "diff_sha256": diff_sha, "files": files}

    proofs = []
    base = (report.get("baseline") or {}).get("detail") or {}
    proofs += _proofs("baseline", base, servers, False, sessions(base))
    if report.get("attempts"):
        last = report["attempts"][-1]
        proofs += _proofs(f"attempt {last['number']}", last.get("detail") or {}, servers, True,
                          sessions(last.get("detail") or {}))

    rows = after if after is not None else report["cbom_before"]
    not_fixed = [{"item": f"{r['path']}:{r['line']} {r['algorithm']}",
                  "reason": f"{r['kind']}: {r['detail']}. {r['nist']}"} for r in rows if not r["auto_fix"]]

    hc_file, hc_sha = art.add_json("host-commands.json", report.get("host_commands", []))
    m = report.get("model") or {}
    if m.get("kind") == "vultr-serverless-inference":
        req_file, req_sha = art.add_json("model-requests.json", m.get("requests", []))
        model = {"provider": "Vultr Serverless Inference", "models": [m.get("id")], "params": m.get("params"),
                 "tokens": m.get("tokens"), "requests_sent": m.get("requests_sent"),
                 "requests_without_usage": m.get("requests_without_usage"),
                 "cost_usd": None if m.get("cost_usd") is None else round(float(m["cost_usd"]), 6),
                 "requests": req_file, "requests_sha256": req_sha}
    else:
        model = {"provider": "none: scripted edits written by hand, no model call", "models": [], "params": None,
                 "tokens": None, "requests_sent": None, "requests_without_usage": None, "cost_usd": None,
                 "requests": None, "requests_sha256": None}

    checks = report.get("checks") or {}
    events = [ev for sb in sandboxes for ev in sb["egress"]["reached_sinkhole"]]
    destroyed = [sb["destroyed_at"] for sb in sandboxes]
    containment = {"policy": POLICY, "canaries_caught": sorted({c for ev in events for c in ev["canaries"]}),
                   "reached_sinkhole": len(events),
                   "reached_sinkhole_not_kept": sum(sb["egress"]["reached_sinkhole_not_kept"] for sb in sandboxes),
                   "dropped_by_policy": DROPPED, "host_build_commands": int(checks.get("host_build_commands") or 0),
                   "guest_build_commands": int(checks.get("guest_build_commands") or 0), "sandboxes": len(sandboxes),
                   "sandboxes_destroyed": sum(1 for d in destroyed if d),
                   "tls_weakening_refused": [int(n) for n in report.get("tls_weakening_refused", [])]}
    receipt = {
        "format": FORMAT, "note": NOTE, "verdict": "pass" if report.get("passed") else "fail",
        "repo": {"url": str(report["repo"]["path"]), "commit": report["repo"]["commit"]},
        "started_at": iso(report["started_at"]), "finished_at": iso(report.get("finished_at") or time.time()),
        "destroyed_at": max(destroyed) if destroyed and all(destroyed) else None,
        "checks": {k: v for k, v in checks.items() if isinstance(v, (bool, int, list)) or v is None},
        "timeline": [{"name": p["name"], "started_at": iso(p["started_at"]), "ended_at": iso(p["ended_at"])}
                     for p in report.get("phases", [])],
        "sandboxes": sandboxes, "probe": report["probe"],
        "plan": {"file": plan_file, "file_sha256": plan_sha, "commands": report["plan"]["commands"],
                 "images": [{k: str(i[k]) for k in ("requested", "pinned", "digest", "architecture")} for i in images],
                 "targets": report["plan"]["targets"]},
        "cbom": {"before": report["cbom_before"], "after": after, "before_file": before_file,
                 "before_file_sha256": before_sha, "after_file": after_file, "after_file_sha256": after_sha},
        "patch": patch, "attempts": attempts, "proofs": proofs, "not_fixed": not_fixed, "containment": containment,
        "model": model, "host_commands": {"file": hc_file, "file_sha256": hc_sha, "count": len(report.get("host_commands", []))},
    }
    receipt["artifacts"] = sorted(art.items.values(), key=lambda i: i["path"])
    receipt["receipt_id"] = compute_id(receipt)
    problems = validate(receipt, SCHEMA)
    if problems:
        raise ValueError("receipt does not fit its schema: " + "; ".join(problems[:10]))
    with open(os.path.join(out, "receipt.json"), "x", encoding="utf-8") as f:
        f.write(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(out, "receipt.html"), "x", encoding="utf-8") as f:
        f.write(render_html(receipt))
    return receipt


# ---------------------------------------------------------------------------------------------
def _hash_refs(value, where="receipt"):
    """(where, path, sha256) for every {X: path, X_sha256: hash} pair in the receipt."""
    out = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key + "_sha256" in value and isinstance(item, str):
                out.append((f"{where}.{key}", item, value[key + "_sha256"]))
            out += _hash_refs(item, f"{where}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            out += _hash_refs(item, f"{where}[{i}]")
    return out


def _listed_files(root):
    out = []
    base = os.path.join(root, "artifacts")
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isdir(full):
                out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(out)


def verify(root):
    """[(ok, what)] for a receipt directory: schema, receipt_id, every artifact's bytes and SHA-256,
    no unlisted file, every *_sha256 field, the inline CBOM against its files, receipt.html."""
    out = []
    try:
        receipt = json.loads(_read_nofollow(root, "receipt.json").decode("utf-8"))
    except (OSError, ValueError) as e:
        return [(False, f"receipt.json cannot be read: {e}")]
    problems = validate(receipt, SCHEMA)
    out.append((not problems, "receipt.json fits the schema" if not problems else
                "receipt.json does not fit the schema:\n  " + "\n  ".join(problems[:20])))
    if problems:
        return out
    got = compute_id(receipt)
    out.append((got == receipt["receipt_id"], f"receipt_id {receipt['receipt_id']}" if got == receipt["receipt_id"]
                else f"receipt_id is {receipt['receipt_id']}, but the receipt hashes to {got}"))
    listed = {}
    for item in receipt["artifacts"]:
        path = item["path"]
        try:
            data = _read_nofollow(root, path)
        except (OSError, ValueError) as e:
            out.append((False, f"{path}: cannot be read ({e})"))
            continue
        digest = hashlib.sha256(data).hexdigest()
        ok = digest == item["sha256"] and len(data) == item["bytes"]
        listed[path] = item["sha256"]
        out.append((ok, f"{path}: sha256 {digest}" if ok else
                    f"{path}: {len(data)} bytes, sha256 {digest}; the receipt says {item['bytes']} bytes, {item['sha256']}"))
    for path in _listed_files(root):
        if path not in listed:
            out.append((False, f"{path}: in the receipt directory but not in the receipt"))
    refs = [(w, p, d) for w, p, d in _hash_refs(receipt) if not (p is None and d is None)]
    bad = [(w, p, d) for w, p, d in refs if listed.get(p) != d]
    for where, path, digest in bad:
        out.append((False, f"{where}: {path} with sha256 {digest} is not an artifact with that hash"))
    if not bad:
        out.append((True, f"all {len(refs)} file references in the receipt name an artifact with the same SHA-256"))
    for side in ("before", "after"):
        path = receipt["cbom"][f"{side}_file"]
        if path in listed:
            same = json.loads(_read_nofollow(root, path).decode("utf-8")) == receipt["cbom"][side]
            out.append((same, f"CBOM {side}: rows match {path}" if same else f"CBOM {side}: rows differ from {path}"))
    try:
        page = _read_nofollow(root, "receipt.html").decode("utf-8")
        same = page == render_html(receipt)
        out.append((same, "receipt.html is this receipt" if same else "receipt.html differs from this receipt"))
    except (OSError, ValueError) as e:
        out.append((False, f"receipt.html cannot be read: {e}"))
    return out


# ---------------------------------------------------------------------------------------------
# The page: rendered from receipt.json alone, deterministically, so verify() can compare it.
SCRIPT = """(function(){var r=document.documentElement,b=document.getElementById('theme');
function set(t){r.setAttribute('data-theme',t);b.textContent=t==='dark'?'Light':'Dark';}
var t='dark';try{t=localStorage.getItem('pqproof-theme')||'dark'}catch(e){}
if(location.hash==='#light')t='light';set(t);
b.addEventListener('click',function(){var n=r.getAttribute('data-theme')==='dark'?'light':'dark';set(n);
try{localStorage.setItem('pqproof-theme',n)}catch(e){}});})();"""
SCRIPT_CSP = "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode() + "'"
STYLE = """:root{color-scheme:dark;--bg:#0f1115;--panel:#171a21;--line:#2a2f3a;--text:#e6e8ee;--muted:#9aa3b2;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--accent:#58a6ff;--code:#0b0d11}
:root[data-theme=light]{color-scheme:light;--bg:#f6f7f9;--panel:#fff;--line:#d8dce3;--text:#1b1f27;--muted:#5b6474;
--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--accent:#0969da;--code:#f0f2f5}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;overflow-wrap:break-word}
main{padding:20px 24px 48px}header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
h1{font-size:22px;margin:0}h2{font-size:17px;margin:28px 0 10px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:13px}
.pass{background:var(--ok);color:#fff}.fail{background:var(--bad);color:#fff}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.muted{color:var(--muted)}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-top:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px 24px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:760px;font-size:13.5px}
td pre{min-width:16em;margin:0}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}code,.hash{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.hash{word-break:break-all;color:var(--muted)}pre{background:var(--code);padding:10px;border-radius:8px;
overflow-x:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px}
a{color:var(--accent)}button{background:var(--panel);color:var(--text);border:1px solid var(--line);
border-radius:8px;padding:6px 12px;font:inherit;cursor:pointer}
.nowrap{white-space:nowrap}"""


def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _short(digest):
    return f'<span class="hash" title="{_e(digest)}">{_e(digest)}</span>' if digest else '<span class="muted">none</span>'


def _link(path, label=None):
    return f'<a href="{_e(path)}">{_e(label or path)}</a>' if path else '<span class="muted">none</span>'


def _table(head, rows):
    out = ['<div class="wrap"><table><thead><tr>'] + [f"<th>{_e(h)}</th>" for h in head] + ["</tr></thead><tbody>"]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
    if not rows:
        out.append(f'<tr><td colspan="{len(head)}" class="muted">none</td></tr>')
    return "".join(out) + "</tbody></table></div>"


def _yes(ok):
    return '<span class="ok">yes</span>' if ok else '<span class="bad">no</span>'


def _cbom_rows(rows):
    return [[f"<code>{_e(r['path'])}:{_e(r['line'])}</code>", _e(r["kind"]), _e(r["algorithm"]), _e(r["detail"]),
             _e(r["nist"]), {True: '<span class="bad">yes</span>', False: "no", None: '<span class="muted">unknown</span>'}[
                 r["blocks_hybrid"]], "yes" if r["auto_fix"] else "no (reported only)"] for r in rows or []]


def render_html(r):
    """receipt.html for a receipt (dict). Everything taken from the receipt is escaped; the page
    loads nothing and links only to its own artifacts."""
    c, m = r["containment"], r["model"]
    verdict = f'<span class="badge {r["verdict"]}">{_e(r["verdict"].upper())}</span>'
    parts = [f"""<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src {SCRIPT_CSP}; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>PQ-Proof receipt</title><style>{STYLE}</style></head><body><main>
<header><h1>PQ-Proof hashed receipt {verdict}</h1><button id="theme" type="button">Light</button></header>
<section><div class="grid">
<div><div class="muted">Repository</div><code>{_e(r['repo']['url'])}</code></div>
<div><div class="muted">Commit</div><span class="hash">{_e(r['repo']['commit'])}</span></div>
<div><div class="muted">Started, finished (UTC)</div><span class="nowrap">{_e(r['started_at'])}</span><br><span class="nowrap">{_e(r['finished_at'])}</span></div>
<div><div class="muted">Last microVM destroyed</div><span class="nowrap">{_e(r['destroyed_at'] or 'not all destroyed')}</span></div>
</div><p><span class="muted">receipt_id</span><br>{_short(r['receipt_id'])}</p>
<p class="muted">{_e(r['note'])}</p><pre>python3 -m pqproof verify-receipt RECEIPT_DIR</pre>
<p class="muted">The verdict comes from handshakes and exit codes below, never from a model.</p></section>"""]

    parts.append("<h2>Proofs</h2><section>" + _table(
        ["Step", "Check", "Expected", "Actual", "Exit", "Matches", "Log (SHA-256)"],
        [[f'<span class="nowrap">{_e(p["step"])}</span>', _e(p["name"]), _e(p["expected"]), _e(p["actual"]), _e(p["exit_code"]), _yes(p["ok"]),
          _link(p["log"], p["log"].rsplit("/", 1)[-1]) + "<br>" + _short(p["log_sha256"])] for p in r["proofs"]]) + "</section>")

    pt = r["patch"]
    parts.append("<h2>Patch</h2><section>" + (
        f"<p>Attempt {_e(pt['attempt'])} changed {_e(', '.join(pt['files']))}: {_link(pt['diff'])} {_short(pt['diff_sha256'])}</p>"
        if pt else '<p class="muted">No attempt passed.</p>') + _table(
        ["Attempt", "Outcome", "Diff", "Error fed back", "TLS-weakening rules"],
        [[_e(a["number"]), _e(a["outcome"]), _link(a["diff"]) + ("<br>" + _short(a["diff_sha256"]) if a["diff"] else ""),
          _link(a["error"]) + ("<br>" + _short(a["error_sha256"]) if a["error"] else ""),
          "<br>".join(_e(w) for w in a["tls_weakening"]) or '<span class="muted">none</span>'] for a in r["attempts"]])
        + "</section>")

    head = ["Where", "Kind", "Algorithm", "Detail", "NIST IR 8547", "Blocks hybrid", "Fixed automatically"]
    parts.append(f"<h2>CBOM before</h2><section><p>{_link(r['cbom']['before_file'])} {_short(r['cbom']['before_file_sha256'])}</p>"
                 + _table(head, _cbom_rows(r["cbom"]["before"])) + "</section>")
    parts.append(f"<h2>CBOM after</h2><section><p>{_link(r['cbom']['after_file'])} {_short(r['cbom']['after_file_sha256'])}</p>"
                 + _table(head, _cbom_rows(r["cbom"]["after"])) + "</section>")
    parts.append("<h2>Not fixed</h2><section>" + _table(["Item", "Why"], [[f"<code>{_e(n['item'])}</code>", _e(n["reason"])]
                                                                          for n in r["not_fixed"]]) + "</section>")

    parts.append(f"""<h2>Containment</h2><section><div class="grid">
<div><div class="muted">Canaries caught in the sinkhole</div><b>{_e(', '.join(c['canaries_caught']) or 'none')}</b></div>
<div><div class="muted">Egress that reached the sinkhole (recorded)</div><b>{_e(c['reached_sinkhole'])}</b> events, {_e(c['reached_sinkhole_not_kept'])} more counted but not kept</div>
<div><div class="muted">Egress dropped by policy</div><b>{_e(c['dropped_by_policy'])}</b>: Microsandbox drops it before the sinkhole</div>
<div><div class="muted">Build commands on the host</div><b>{_e(c['host_build_commands'])}</b> (in microVMs: {_e(c['guest_build_commands'])})</div>
<div><div class="muted">MicroVMs destroyed</div><b>{_e(c['sandboxes_destroyed'])} of {_e(c['sandboxes'])}</b></div>
<div><div class="muted">Patches refused for weakening TLS</div><b>{_e(', '.join(f'attempt {n}' for n in c['tls_weakening_refused']) or 'none')}</b></div>
</div><p class="muted">Policy</p><ul>{''.join(f'<li>{_e(p)}</li>' for p in c['policy'])}</ul></section>""")
    events = [[_e(sb["step"]), _e(ev["kind"]), f"<code>{_e(ev['dest'])}</code>", _e(ev["bytes"]), _e(", ".join(ev["canaries"]) or "none"),
               f"<pre>{_e(ev['preview'])}</pre>", _short(ev["sha256"])] for sb in r["sandboxes"] for ev in sb["egress"]["reached_sinkhole"]]
    parts.append("<h2>Egress that reached the sinkhole</h2><section>" + _table(
        ["Step", "Kind", "Destination", "Bytes", "Canaries", "First bytes", "SHA-256 of the bytes"], events) + "</section>")
    parts.append("<h2>MicroVMs</h2><section>" + _table(
        ["Step", "MicroVM", "Image", "Limits", "Started, destroyed (UTC)", "Network flags", "Commands"],
        [[_e(sb["step"]), f"<code>{_e(sb['id'])}</code>", f"<code>{_e(sb['image'].partition('@')[0])}</code><br>{_short(sb['image_digest'].partition(':')[2])}"
          + (f"<br><span class=\"muted\">{_e(sb['architecture'])}</span>" if sb["architecture"] else ""),
          _e(f"{sb['limits']['cpus']} vCPU, {sb['limits']['memory_mib']} MiB, {sb['limits']['wall_clock_s']} s"),
          f"<span class=\"nowrap\">{_e(sb['started_at'])}</span><br><span class=\"nowrap\">{_e(sb['destroyed_at'] or 'not destroyed')}</span>",
          "<br>".join(f"<code>{_e(n)}</code>" for n in sb["network"]), _e(f"{len(sb['execs'])} in the guest, {sb['msb_commands']} msb")]
         for sb in r["sandboxes"]]) + "</section>")
    p = r["probe"]
    parts.append(f"""<h2>Probe and plan</h2><section><div class="grid">
<div><div class="muted">Probe</div>{_e(p['name'])} {_e(p['version'])}, built in a microVM from <code>{_e(p['built_with'].partition('@')[0])}</code><br>binary {_short(p['sha256'])}<br>source {_short(p['source_sha256'])}</div>
<div><div class="muted">Approved plan</div>{_link(r['plan']['file'])} {_short(r['plan']['file_sha256'])}<br>{_e(len(r['plan']['commands']))} commands, {_e(len(r['plan']['images']))} images, targets {_e(', '.join(t['addr'] + ' (' + t['server'] + ')' for t in r['plan']['targets']))}</div>
<div><div class="muted">Model</div>{_e(m['provider'])}{(' ' + _e(', '.join(m['models']))) if m['models'] else ''}<br>{_e(f"{m['requests_sent']} requests, {(m['tokens'] or {}).get('prompt_tokens', 0)} prompt + {(m['tokens'] or {}).get('completion_tokens', 0)} completion tokens, ${m['cost_usd']}") if m['tokens'] else ''}{('<br>' + _link(m['requests']) + ' ' + _short(m['requests_sha256'])) if m['requests'] else ''}</div>
<div><div class="muted">Host command lines</div>{_link(r['host_commands']['file'])} ({_e(r['host_commands']['count'])}) {_short(r['host_commands']['file_sha256'])}</div>
</div></section>""")
    parts.append("<h2>Timeline</h2><section>" + _table(["Phase", "Started (UTC)", "Ended (UTC)"], [
        [_e(t["name"]), f'<span class="nowrap">{_e(t["started_at"])}</span>', f'<span class="nowrap">{_e(t["ended_at"])}</span>']
        for t in r["timeline"]]) + "</section>")
    parts.append("<h2>Artifacts</h2><section>" + _table(["File", "Bytes", "SHA-256"], [
        [_link(a["path"]), _e(a["bytes"]), _short(a["sha256"])] for a in r["artifacts"]]) + "</section>")
    parts.append(f"</main><script>{SCRIPT}</script></body></html>\n")
    return "".join(parts)


def main(argv):
    """verify-receipt DIR: print each check, exit 0 only when all pass."""
    if len(argv) != 1:
        print("usage: python3 -m pqproof verify-receipt RECEIPT_DIR")
        return 2
    results = verify(argv[0])
    for ok, what in results:
        print(f"{'ok  ' if ok else 'FAIL'} {what}")
    bad = sum(1 for ok, _ in results if not ok)
    print(f"{'all checks pass' if not bad else f'{bad} check(s) failed'} ({len(results)} checks)")
    return 0 if not bad else 1
