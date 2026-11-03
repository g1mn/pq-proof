"""Base images PQ-Proof itself uses, pinned by OCI image index digest.

An index digest names one multi-platform image, so the same pin works on the Mac (linux/arm64
guests) and on the Vultr VX1 host (linux/amd64). Measured on macOS with msb 0.7.13 (2026-11-04):
`msb pull name:tag@sha256:<index>` resolves the index to the host's platform, and
`msb image inspect` then reports the platform manifest digest, not the index digest. Receipts
record that platform digest next to the index pin. The per-platform digests below come from
Docker Hub's tag API on 2026-11-04; amd64 has not been pulled on a VX1 host yet.
"""
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Image:
    name: str
    tag: str
    index: str
    platforms: dict

    @property
    def ref(self):
        return f"{self.name}:{self.tag}@{self.index}"


# Builds Go code: the probe here, the target repo's API in the e2e run.
GOLANG = Image("golang", "1.27-bookworm",
               "sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9",
               {"arm64": "sha256:ae675cdbf1bb782b6de4a56b157c8f91a5c89a594d8fa6475bb71efc4be3cfcb",
                "amd64": "sha256:e482b31b5d30c31f9e495f4b8cbdf41429b2d74955dfbcd9c0a904483d738390"})
# Debian 12: OpenSSL 3.0.17 inside (measured), no ML-KEM. orders-edge's original runtime image.
NGINX_BOOKWORM = Image("nginx", "1.28-bookworm",
                       "sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609",
                       {"arm64": "sha256:b869934f513dcd08fc9de959e0bf6175e47ff3553a9c127afce9969722304356",
                        "amd64": "sha256:3b03dfd827515a07ccf4946000f0bbdd2a4fb6aca7499249fcb6b1f9726823d6"})
# Debian 13: OpenSSL 3.5.7 inside (measured), has ML-KEM.
NGINX_TRIXIE = Image("nginx", "1.30-trixie",
                     "sha256:66b50d24288dba67f3d000b31223daefc4868c58d29aaacb6a4ff9771597b5eb",
                     {"arm64": "sha256:0a63e6c31fb62d0647c8d37fa88219af4ecfc130639a36a4686634b15b606f29",
                      "amd64": "sha256:b565a9579cdabe43de09a5a278dc95ceee721dae1cacf85247effc4f6630d511"})


@dataclass(frozen=True)
class Resolved:
    requested: str
    pinned: str  # name:tag@sha256:<platform manifest digest>, what the approver sees and the allowlist holds
    digest: str
    architecture: str

    def show(self):
        return f"{self.requested} -> {self.pinned} (linux/{self.architecture})"


def resolve(ref, run, msb="msb"):
    """Turn an image the model named (name:tag) into name:tag@sha256:<digest> before approval.

    The control plane pulls it (`msb pull`, on the host, never in a sandbox) and reads the digest
    with `msb image inspect`, which reports this host's platform manifest. The same tag on the VX1
    (amd64) gives a different digest than on a Mac (arm64). A ref that already carries a digest
    (index or platform) is pulled by that digest, and the result names the platform digest msb
    reports. run(argv, timeout) -> CompletedProcess, like sandbox.run_cmd.
    """
    from .plan import OFFICIAL, PlanError  # noqa: PLC0415 - plan imports nothing from here
    base, _, want = ref.partition("@")
    name, _, tag = base.partition(":")
    if not tag or not OFFICIAL.fullmatch(name) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag) \
            or tag == "latest" or (want and not re.fullmatch(r"sha256:[0-9a-f]{64}", want)):
        raise PlanError(f"image must be a Docker Hub official name:tag (not latest), optionally @sha256: {ref!r}")
    for argv in ([msb, "pull", "-q", ref], [msb, "image", "inspect", ref, "--format", "json"]):
        r = run(argv, timeout=900)
        if r.returncode != 0:
            raise PlanError(f"{' '.join(argv[:3])} failed: {str(r.stderr).strip()[-300:]}")
    info = json.loads(str(r.stdout))
    digest, arch = info["digest"], info.get("architecture", "?")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PlanError(f"msb reported no digest for {ref!r}")
    pinned = f"{base}@{digest}"
    if pinned != ref:  # cache it under the pinned name too (layers are already here, so no download)
        r = run([msb, "pull", "-q", pinned], timeout=900)
        if r.returncode != 0:
            raise PlanError(f"msb pull {pinned} failed: {str(r.stderr).strip()[-300:]}")
    return Resolved(requested=ref, pinned=pinned, digest=digest, architecture=arch)
