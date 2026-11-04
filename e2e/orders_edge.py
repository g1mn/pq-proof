"""End-to-end run on the orders-edge fixture, with real microVMs and a scripted stand-in for the model.

    python3 e2e/orders_edge.py --repo ../orders-edge [--out runs/e2e] [--approve]

1. Snapshot: `git clone --no-recurse-submodules`, then a copy without .git (host: git only).
2. CBOM before (reads files only).
3. Plan from e2e/orders-edge-scripted-model.json; its image tags are resolved to
   name:tag@sha256:<platform digest> with msb pull + msb image inspect and shown for approval.
4. tls_probe built inside a microVM.
5. Baseline: build and prove the unmodified snapshot. Expected: both probe controls hold, hybrid
   fails on every target, the classical client still connects.
6. Patch loop (at most 3 attempts) with the scripted edits; each failure's raw output is fed back.
7. CBOM after, then checks: the final build negotiates X25519MLKEM768 on every target and the
   classical client still connects; every build and server command ran inside `msb exec` (host
   build commands: 0); the planted test hook's canary landed in the sinkhole; no sandbox is left.
Exit code 0 only when every check passes. The report (JSON) goes to --out.

The edits are fixed and written by hand (see the JSON file's note): this run shows the
containment, build, feedback and proof machinery, not model quality. No inference call is made.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pqproof import prove  # noqa: E402
from pqproof.egress import Sinkhole  # noqa: E402
from pqproof.images import GOLANG, NGINX_BOOKWORM, NGINX_TRIXIE, resolve  # noqa: E402
from pqproof.loop import ScriptedModel, run_loop  # noqa: E402
from pqproof.pipeline import Pipeline, guest_commands, host_build_count, tls_layout  # noqa: E402
from pqproof.plan import compile_allowlist  # noqa: E402
from pqproof.sandbox import LABEL, MSB, Runner, run_cmd  # noqa: E402
from pqproof.scan import scan  # noqa: E402

MODEL_FILE = ROOT / "e2e" / "orders-edge-scripted-model.json"
# orders-edge serves TLS on two ports: nginx (the edge) and the Go API behind it. Both must be probed,
# each must be answered by its own server.
EXPECTED_TARGETS = [("127.0.0.1:8443", "nginx"), ("127.0.0.1:9443", "api")]
# Tags PQ-Proof already pins by index digest: resolve through the pin, so a moved tag cannot change a run.
KNOWN = {f"{i.name}:{i.tag}": i.ref for i in (GOLANG, NGINX_BOOKWORM, NGINX_TRIXIE)}


class Recorder:
    """Every command line the control plane runs on the host, in order."""

    def __init__(self):
        self.argvs = []

    def run(self, argv, timeout=None):
        self.argvs.append(list(argv))
        return run_cmd(argv, timeout=timeout)


def snapshot(repo, dest, rec):
    clone = dest + ".clone"
    argv = ["git", "clone", "-q", "--no-recurse-submodules", "--no-hardlinks", os.fspath(repo), clone]
    rec.argvs.append(argv)
    subprocess.run(argv, check=True, env={"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0"})
    commit = subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    rec.argvs.append(["git", "-C", clone, "rev-parse", "HEAD"])
    shutil.copytree(clone, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return commit


def baseline_ok(res, targets):
    v = res.detail.get("verdict") or {}
    t = v.get("targets", {})
    neg = v.get("negative_control") or {}
    return ("build" in res.detail and (v.get("positive_control") or {}).get("kind") == "hybrid"
            and (neg.get("hybrid") or {}).get("kind") == "failed" and (neg.get("classical") or {}).get("kind") == "classical"
            and bool(targets) and sorted(t) == sorted(targets)
            and all(t[x].get("hybrid", {}).get("kind") == "failed" and
                    t[x].get("classical", {}).get("kind") in ("classical", "hybrid") for x in targets))


def final_ok(res, targets):
    t = (res.detail.get("verdict") or {}).get("targets", {})
    return (res.ok and bool(targets) and sorted(t) == sorted(targets)
            and all(t[x].get("hybrid", {}).get("group") == "X25519MLKEM768" and
                    t[x].get("classical", {}).get("kind") == "classical" for x in targets))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", default=str(ROOT / "runs" / time.strftime("e2e-%Y%m%dT%H%M%S")))
    ap.add_argument("--approve", action="store_true", help="approve the plan without asking")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True)
    rec = Recorder()
    model_doc = json.loads(MODEL_FILE.read_text())
    report = {"started_at": time.time(), "model": {"kind": "scripted", "note": model_doc["note"], "file": MODEL_FILE.name}}
    t0 = time.time()

    with tempfile.TemporaryDirectory(prefix="pqproof-e2e-") as scratch, Sinkhole() as sink:
        runner = Runner(msb=MSB, run=rec.run, egress=sink)
        # removes sandboxes a killed earlier run left behind, now and every minute (only stopped ones
        # or ones older than the longest step's wall clock, so never a live step of this run)
        stop_reaper = runner.start_reaper()
        snap = os.path.join(scratch, "snapshot")
        report["repo"] = {"path": os.fspath(args.repo), "commit": snapshot(args.repo, snap, rec)}
        report["cbom_before"] = [r.to_json() for r in scan(snap)]

        plan = json.loads(json.dumps(model_doc["plan"]))
        resolved = [resolve(KNOWN.get(img, img), rec.run, msb=MSB) for img in plan["images"]]
        pins = {img: r.pinned for img, r in zip(plan["images"], resolved)}
        plan["images"] = [r.pinned for r in resolved]
        print("Plan:", plan["summary"])
        for img, r in zip(model_doc["plan"]["images"], resolved):
            print(f"  image {img} -> {r.pinned} (linux/{r.architecture})")
        for e in plan["edits"]:
            print(f"  edit  {e['path']}: {e['why']}")
        for c in plan["commands"]:
            print(f"  run   {' '.join(c)}")
        for t in plan["targets"]:
            print(f"  probe {t['addr']} (must be served by {t['server']})")
        if not args.approve and input("Approve this plan? [y/N] ").strip().lower() != "y":
            print("not approved")
            return 2
        report["plan"], report["images"] = plan, [vars(r) for r in resolved]
        allow = compile_allowlist(plan)

        probe = prove.build_probe(runner, scratch)
        sink.take()
        report["probe"] = probe.to_json()
        print(f"probe: {probe.name} {probe.version} sha256 {probe.sha256}")

        layout = tls_layout(snap)
        pipe = Pipeline(runner, allow, probe, layout, pins, "e2e", scratch, sink)
        targets = [a for a, _ in sorted(allow.targets)]

        base_dir = os.path.join(scratch, "baseline")
        shutil.copytree(snap, base_dir, symlinks=True)
        base = pipe.build_and_prove(base_dir, 0)
        report["baseline"] = {"ok": base.ok, "raw_error": base.raw_error, "detail": base.detail}
        print("baseline:", json.dumps((base.detail.get("verdict") or {}).get("targets")))

        model = ScriptedModel(model_doc["attempts"])
        outcome = run_loop(model, snap, allow, pipe.build_and_prove, scratch,
                           context={"cbom": report["cbom_before"], "plan": plan})
        report["attempts"] = [{"number": a.number, "edits": a.edits, "diff": a.diff, "ok": a.result.ok,
                               "raw_error": a.result.raw_error, "detail": a.result.detail} for a in outcome.attempts]
        report["model"]["feedback_seen"] = [{"attempt": n, "feedback": f} for n, f in model.calls]
        for a in outcome.attempts:
            print(f"attempt {a.number}: {'ok' if a.result.ok else 'failed'}"
                  + ("" if a.result.ok else f" -- {a.result.raw_error.splitlines()[0]} ..."))
        final = outcome.attempts[-1].result
        report["cbom_after"] = [r.to_json() for r in scan(outcome.workdir)] if outcome.ok else None
        stop_reaper.set()

    # checks
    every_step = [report["baseline"]["detail"]] + [a["detail"] for a in report["attempts"]]
    sessions = [d[k] for d in every_step for k in ("build", "prove") if k in d]
    host = rec.argvs
    guest = guest_commands(host, MSB)
    left = json.loads(run_cmd([MSB, "ls", "--label", LABEL, "--format", "json"], timeout=60).stdout or "[]")
    canaries = sorted({c for s in sessions for c in s["egress"]["canaries"]})
    checks = {
        "targets_are_orders_edge_ports": sorted(allow.targets) == EXPECTED_TARGETS,
        "baseline_hybrid_fails_classical_connects": baseline_ok(base, targets),
        "patched_negotiates_X25519MLKEM768_classical_connects": final_ok(final, targets),
        "attempts_at_most_3": 1 <= len(report["attempts"]) <= 3,
        "host_build_commands": host_build_count(host, MSB),
        "guest_build_commands": sum(1 for g in guest if g[:1] in (["make"], ["go"]) or g[:2] == ["nginx", "-t"]),
        "every_sandbox_destroyed": all(s["destroyed_at"] for s in sessions) and not left,
        "canaries_in_sinkhole": canaries,
        "cbom_after_blocking_rows": None if report["cbom_after"] is None else
        [r for r in report["cbom_after"] if r["blocks_hybrid"]],
        # a runtime image the CBOM cannot place is not a clean bill either
        "cbom_after_unknown_rows": None if report["cbom_after"] is None else
        [r for r in report["cbom_after"] if r["blocks_hybrid"] is None],
    }
    passed = (checks["targets_are_orders_edge_ports"] and checks["baseline_hybrid_fails_classical_connects"]
              and checks["patched_negotiates_X25519MLKEM768_classical_connects"] and checks["attempts_at_most_3"] and checks["host_build_commands"] == 0 and checks["guest_build_commands"] > 0
              and checks["every_sandbox_destroyed"] and "CANARY-0001" in canaries and checks["cbom_after_blocking_rows"] == [] and checks["cbom_after_unknown_rows"] == [])
    report.update(host_commands=host, checks=checks, passed=passed, seconds=round(time.time() - t0, 1))
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(checks, indent=2))
    print(f"{'PASS' if passed else 'FAIL'} in {report['seconds']} s; report: {out / 'report.json'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
