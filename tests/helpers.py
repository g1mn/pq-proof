"""Shared test helpers: allowlists for the runner and the real-msb switch."""
import json
import os
import shutil
import subprocess

from pqproof.plan import Allowlist
from pqproof.sandbox import MSB


def allow(image, *commands):
    """An approved allowlist that holds exactly this image and these command lines."""
    return Allowlist(commands=frozenset(tuple(c) for c in commands), paths=frozenset(),
                     images=frozenset({image}))


def msb_available():
    return os.environ.get("PQPROOF_MSB_TESTS", "1") != "0" and shutil.which(MSB) is not None


def pinned(image="alpine"):
    """Pull `image` (network on the first run only) and return it as name@sha256:<digest>, cached."""
    def msb(*args):
        return subprocess.run([MSB, *args], check=True, capture_output=True, text=True, timeout=300).stdout
    msb("pull", "-q", image)
    ref = f"{image}@{json.loads(msb('image', 'inspect', image, '--format', 'json'))['digest']}"
    msb("pull", "-q", ref)
    return ref
