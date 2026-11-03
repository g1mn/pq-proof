"""CBOM scanner: the F1 (orders-edge) snapshot gives the expected rows, and nothing is followed or run."""
import os
import pathlib
import tempfile
import unittest

from pqproof.scan import HYBRID, dockerfile_images, scan

F1 = pathlib.Path(__file__).resolve().parent / "fixtures" / "f1"


def rows_of(files):
    with tempfile.TemporaryDirectory() as d:
        for path, text in files.items():
            p = pathlib.Path(d, path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return scan(d)


class F1Snapshot(unittest.TestCase):
    def test_expected_rows(self):
        got = [(r.path, r.line, r.kind, r.algorithm, r.blocks_hybrid, r.auto_fix) for r in scan(F1)]
        self.assertEqual(got, [
            ("Dockerfile", 8, "base-image", "nginx:1.28-bookworm", True, True),
            ("go.mod", 3, "toolchain", "go 1.22", True, True),
            ("internal/auth/jwt.go", 29, "signature", "JWT RS256 (RSA)", False, False),
            ("internal/tlsconf/tlsconf.go", 12, "key-exchange", "P-256", True, True),
            ("nginx/nginx.conf", 21, "key-exchange", "P-256", True, True),
        ])

    def test_two_curve_pins_and_nist_status(self):
        pins = [r for r in scan(F1) if r.kind == "key-exchange"]
        self.assertEqual({r.component for r in pins}, {"nginx", "go"})
        for r in pins:
            self.assertIn("deprecated after 2030, disallowed after 2035", r.nist)
            self.assertIn(f"no {HYBRID}", r.detail)
        jwt = [r for r in scan(F1) if r.kind == "signature"][0]
        self.assertIn("Table 2", jwt.nist)

    def test_vendor_and_tests_are_skipped(self):
        paths = {r.path for r in scan(F1)}
        self.assertFalse(any(p.startswith("vendor/") or p.endswith("_test.go") for p in paths), paths)

    def test_rows_serialise(self):
        row = scan(F1)[0].to_json()
        self.assertEqual(set(row), {"path", "line", "component", "kind", "algorithm", "detail", "nist",
                                    "blocks_hybrid", "auto_fix"})


class Rules(unittest.TestCase):
    def test_hybrid_nginx_and_go_do_not_block(self):
        rows = rows_of({
            "nginx.conf": "server {\n ssl_certificate a;\n ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n}\n",
            "tls.go": "package x\nvar c = tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}}\n",
        })
        self.assertEqual([(r.algorithm, r.blocks_hybrid) for r in rows],
                         [("X25519MLKEM768, X25519, P-256", False)] * 2)

    def test_go_mod_versions(self):
        self.assertEqual([r.algorithm for r in rows_of({"go.mod": "module m\n\ngo 1.23.4\n"})], ["go 1.23"])
        self.assertEqual(rows_of({"go.mod": "module m\n\ngo 1.24\n"}), [])
        self.assertEqual(rows_of({"go.mod": "module m\n\ngo 1.27.3\n"}), [])

    def test_runtime_stage_is_the_last_from(self):
        text = "FROM golang:1.27-bookworm AS build\nRUN true\nFROM --platform=linux/amd64 nginx:1.30-trixie@sha256:" + "a" * 64 + "\n"
        self.assertEqual([i for _, i, _ in dockerfile_images(text)],
                         ["golang:1.27-bookworm", "nginx:1.30-trixie@sha256:" + "a" * 64])
        (row,) = rows_of({"Dockerfile": text})
        self.assertEqual((row.line, row.blocks_hybrid), (3, False))
        (row,) = rows_of({"Dockerfile": "FROM debian:bullseye-slim\n"})
        self.assertTrue(row.blocks_hybrid)
        (row,) = rows_of({"Dockerfile": "FROM nginx:1.30-alpine\n"})
        self.assertEqual((row.nist, row.blocks_hybrid), ("unknown", False))

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as snap:
            pathlib.Path(outside, "x.conf").write_text("ssl_ecdh_curve prime256v1;\n")
            pathlib.Path(outside, "d").mkdir()
            pathlib.Path(outside, "d", "y.conf").write_text("ssl_ecdh_curve prime256v1;\n")
            os.symlink(os.path.join(outside, "x.conf"), os.path.join(snap, "edge.conf"))
            os.symlink(os.path.join(outside, "d"), os.path.join(snap, "conf.d"))
            self.assertEqual(scan(snap), [])

    def test_ecdsa_jwt_is_a_signature_row(self):
        (row,) = rows_of({"a.go": 'package a\nvar m = jwt.SigningMethodES256\n'})
        self.assertEqual((row.kind, row.algorithm, row.auto_fix), ("signature", "JWT ES256 (ECDSA)", False))


if __name__ == "__main__":
    unittest.main()
