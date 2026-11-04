"""Repo hygiene: MIT license present, secrets ignored by git."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class RepoHygiene(unittest.TestCase):
    def test_mit_license(self):
        text = (ROOT / "LICENSE").read_text()
        self.assertTrue(text.startswith("MIT License"))
        self.assertIn("Copyright (c) 2026 g1mn", text)

    def test_secret_files_are_ignored(self):
        # Checked in a scratch repository holding this .gitignore, so the test also runs on a copy
        # without .git (deploy/upload.sh sends `git archive` output to the host).
        with tempfile.TemporaryDirectory() as repo:
            shutil.copy(ROOT / ".gitignore", repo)
            subprocess.run(["git", "init", "-q", repo], check=True)
            for name in (".env", ".env.local", "inference.env", "server.key", "id_ed25519"):
                with self.subTest(name=name):
                    r = subprocess.run(["git", "-C", repo, "check-ignore", "-q", name])
                    self.assertEqual(r.returncode, 0, f"{name} is not ignored")


if __name__ == "__main__":
    unittest.main()
