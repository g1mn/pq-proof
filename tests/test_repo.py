"""Repo hygiene: MIT license present, secrets ignored by git."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class RepoHygiene(unittest.TestCase):
    def test_mit_license(self):
        text = (ROOT / "LICENSE").read_text()
        self.assertTrue(text.startswith("MIT License"))
        self.assertIn("Copyright (c) 2026 g1mn", text)

    def test_secret_files_are_ignored(self):
        for name in (".env", ".env.local", "inference.env", "server.key", "id_ed25519"):
            with self.subTest(name=name):
                r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", name])
                self.assertEqual(r.returncode, 0, f"{name} is not ignored")


if __name__ == "__main__":
    unittest.main()
