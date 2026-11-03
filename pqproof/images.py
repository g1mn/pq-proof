"""Base images PQ-Proof itself uses, pinned by OCI image index digest.

An index digest names one multi-platform image, so the same pin works on the Mac (linux/arm64
guests) and on the Vultr VX1 host (linux/amd64). Measured on macOS with msb 0.7.13 (2026-11-04):
`msb pull name:tag@sha256:<index>` resolves the index to the host's platform, and
`msb image inspect` then reports the platform manifest digest, not the index digest. Receipts
record that platform digest next to the index pin. The per-platform digests below come from
Docker Hub's tag API on 2026-11-04; amd64 has not been pulled on a VX1 host yet.
"""
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
