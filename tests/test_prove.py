"""prove: output parsing (hybrid, classical, failed), the probe's fixed commands, and a real run.

The integration tests build tls_probe inside a microVM and run it in nginx:1.28-bookworm (whose own
OpenSSL 3.0 has no ML-KEM): positive control, classical and failed. They need msb and the pinned
golang and nginx images in the local cache, and are skipped otherwise.
"""
import hashlib
import pathlib
import subprocess
import tempfile
import unittest

from helpers import msb_available
from pqproof import prove
from pqproof.images import GOLANG, NGINX_BOOKWORM
from pqproof.plan import Allowlist, PlanError, check_command
from pqproof.sandbox import MSB, Runner

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "probe"


def fixture(name):
    return (FIX / name).read_text()


class Parse(unittest.TestCase):
    def test_openssl_three_outputs(self):
        cases = {
            # hybrid: the group is on its own line
            "openssl-hybrid.txt": ("hybrid", "X25519MLKEM768", "TLSv1.3"),
            # classical: no "Negotiated TLS1.3 group" line, only "Peer Temp Key: X25519, 253 bits"
            "openssl-classical.txt": ("classical", "X25519", "TLSv1.3"),
            # failed: alert 40, and "Negotiated TLS1.3 group NID: 0" is not a group
            "openssl-failure.txt": ("failed", None, None),
        }
        for name, (kind, group, proto) in cases.items():
            with self.subTest(name=name):
                h = prove.parse(fixture(name))
                self.assertEqual((h.kind, h.group, h.protocol, h.client), (kind, group, proto, "openssl"))
        classical = fixture("openssl-classical.txt")
        self.assertNotIn("Negotiated TLS1.3 group", classical)
        self.assertIn("Peer Temp Key: X25519, 253 bits", classical)
        self.assertIn("alert number 40", prove.parse(fixture("openssl-failure.txt")).error)

    def test_tls_probe_three_outputs(self):
        cases = {"tls_probe-hybrid.txt": ("hybrid", "X25519MLKEM768"),
                 "tls_probe-classical.txt": ("classical", "X25519"),
                 "tls_probe-failure.txt": ("failed", None)}
        for name, (kind, group) in cases.items():
            with self.subTest(name=name):
                h = prove.parse(fixture(name))
                self.assertEqual((h.kind, h.group, h.client), (kind, group, "tls_probe"))
        self.assertEqual(prove.parse(fixture("tls_probe-failure.txt")).error, "remote error: tls: handshake failure")

    def test_nothing_is_not_a_success(self):
        for text in ("", "garbage", "Negotiated TLS1.3 group: X25519MLKEM768\n"):  # a group line alone proves nothing
            with self.subTest(text=text):
                self.assertEqual(prove.parse(text).kind, "failed")

    def test_other_hybrid_groups_count_as_hybrid(self):
        h = prove.parse("result: connected\nprotocol: TLS 1.3\ngroup: SecP256r1MLKEM768\n")
        self.assertEqual(h.kind, "hybrid")
        self.assertEqual(prove.parse("result: connected\ngroup: P-256\n").kind, "classical")


class FixedCommands(unittest.TestCase):
    def test_control_problem(self):
        def r(text):
            return prove.parse(text), type("E", (), {"stdout": text, "stderr": ""})()
        hybrid = "result: connected\ngroup: X25519MLKEM768\n"
        x25519 = "result: connected\ngroup: X25519\n"
        failed = "result: failed\nerror: remote error: tls: handshake failure\n"
        good = {"positive": r(hybrid), "negative_hybrid": r(failed), "negative_classical": r(x25519)}
        self.assertIsNone(prove.control_problem(good))
        for name, text, why in (("positive", failed, "positive control"), ("negative_hybrid", hybrid, "negative control"),
                                ("negative_classical", failed, "negative control")):
            with self.subTest(name=name):
                self.assertIn(why, prove.control_problem({**good, name: r(text)}))

    def test_every_probe_command_fits_the_program_allowlist(self):
        allow = prove.probe_allowlist(["127.0.0.1:8443", "127.0.0.1:9443"], "/etc/orders-edge/tls",
                                      servername="orders-edge.local", hosts="localhost,127.0.0.1,orders-edge.local")
        self.assertGreaterEqual(len(allow.commands), 8)
        for argv in allow.commands | {prove.BUILD_PROBE}:
            with self.subTest(argv=argv):
                self.assertEqual(check_command(list(argv)), argv)

    def test_probe_shapes_refuse_other_hosts_and_relative_paths(self):
        for argv in (["tls_probe", "connect", "-groups=X25519", "-ca=/a/ca.pem", "8.8.8.8:443"],
                     ["tls_probe", "serve", "-addr=0.0.0.0:4433"],
                     ["tls_probe", "connect", "-ca=ca.pem", "127.0.0.1:1"],
                     ["tls_probe", "exec", "/bin/sh"],
                     ["go", "build", "-o=../api", "."], ["go", "build", "-o=/usr/bin/api", "."],
                     ["go", "build", "-o=.hidden/api", "."], ["go", "build", "-o", "api", "."]):
            with self.subTest(argv=argv), self.assertRaises(PlanError):
                check_command(argv)

    def test_probe_record(self):
        p = prove.Probe(name="tls_probe", version="0.1.0", sha256="a" * 64, source_sha256="b" * 64,
                        built_with=GOLANG.ref, path="/tmp/x")
        self.assertEqual(p.to_json(), {"name": "tls_probe", "version": "0.1.0", "sha256": "a" * 64,
                                       "source_sha256": "b" * 64, "built_with": GOLANG.ref})
        self.assertEqual(len(prove.source_sha256()), 64)


def cached(ref):
    return subprocess.run([MSB, "image", "inspect", ref], capture_output=True).returncode == 0


@unittest.skipUnless(msb_available(), "msb not installed or PQPROOF_MSB_TESTS=0")
class RealProbe(unittest.TestCase):
    TLS = "/etc/pqproof-tls"

    @classmethod
    def setUpClass(cls):
        for img in (GOLANG.ref, NGINX_BOOKWORM.ref):
            if not cached(img):
                raise unittest.SkipTest(f"image not cached: msb pull {img}")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.runner = Runner()
        cls.probe = prove.build_probe(cls.runner, cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_probe_is_recorded_by_name_version_and_hash(self):
        data = pathlib.Path(self.probe.path).read_bytes()
        self.assertEqual(self.probe.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual((self.probe.name, self.probe.version, self.probe.built_with),
                         ("tls_probe", prove.PROBE_VERSION, GOLANG.ref))
        self.assertTrue(data.startswith(b"\x7fELF"))

    def test_controls_classical_and_failed_in_an_openssl_30_image(self):
        weak = ("tls_probe", "serve", "-addr=127.0.0.1:4435", "-groups=P-256",
                f"-cert={self.TLS}/cert.pem", f"-key={self.TLS}/key.pem")
        allow = prove.probe_allowlist([prove.CONTROL_ADDR, "127.0.0.1:4435"], self.TLS).union(
            Allowlist(commands=frozenset({weak}), paths=frozenset(), images=frozenset({NGINX_BOOKWORM.ref})))
        with self.runner.session(allow, "probe", "test", NGINX_BOOKWORM.ref) as s:
            version = prove.install_probe(s, self.probe, self.TLS)
            prove.start_references(s, self.TLS)
            ctl = prove.controls(s, self.TLS)
            vs_control = prove.probe_target(s, prove.CONTROL_ADDR, self.TLS)
            s.start(list(weak))
            vs_weak = prove.probe_target(s, "127.0.0.1:4435", self.TLS)
        self.assertRegex(version, rf"^tls_probe {prove.PROBE_VERSION.replace('.', chr(92) + '.')} \(go1\.\d+")
        self.assertIsNone(prove.control_problem(ctl))
        self.assertEqual((ctl["positive"][0].kind, ctl["positive"][0].group), ("hybrid", "X25519MLKEM768"))
        self.assertEqual(ctl["negative_hybrid"][0].kind, "failed")  # X25519-only reference server
        self.assertEqual((ctl["negative_classical"][0].kind, ctl["negative_classical"][0].group), ("classical", "X25519"))
        self.assertEqual((vs_control["classical"][0].kind, vs_control["classical"][0].group), ("classical", "X25519"))
        self.assertEqual(vs_weak["hybrid"][0].kind, "failed")
        self.assertEqual((vs_weak["classical"][0].kind, vs_weak["classical"][0].group), ("classical", "P-256"))
        self.assertIsNotNone(s.destroyed_at)
        self.assertTrue(all(c[0] == MSB for c in s.host_commands))


if __name__ == "__main__":
    unittest.main()
