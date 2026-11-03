# PQ-Proof

Give PQ-Proof a repository URL. An agent inventories the repo's cryptography, patches its TLS key exchange to hybrid ML-KEM (`X25519MLKEM768`), and proves the change inside isolated microVMs on Vultr: a real handshake, the repo's own tests, and a classical client that still connects. You get a hashed receipt and a diff.

> **Status:** under construction for the Vultr Agent Rush hackathon (November 2026). Parts marked *planned* are not in this repository yet.

## Architecture (draft)

The control plane is one Python (3.12+) process that sticks to the standard library where it can. It drives [Microsandbox](https://github.com/superradcompany/microsandbox) through the `msb` CLI from the official installer, so every action that touches a sandbox is a plain command line that is logged and can go into the receipt. Model calls go to Vultr Serverless Inference's OpenAI-compatible `/v1/chat/completions` endpoint over `urllib`; the agent needs no SDK, and the API key never leaves the control plane. Repo snapshots and receipts go to Vultr Object Storage through `boto3`, the standard S3 client (*planned*). The web UI is a single static HTML page with plain JavaScript, served by the same process, with no build step (*planned*). We chose Python because Microsandbox's docs and Vultr's sandboxing guide both use it, Ubuntu 24.04 on the VX1 host ships Python 3.12, and this is a one-person, 4.5-day build.

```
browser --HTTPS--> control plane (Python, Vultr VX1)
                     |- Vultr Serverless Inference   plan, patch, tool calls (key stays here)
                     |- Vultr Object Storage         snapshot in, receipt out (planned)
                     '- msb create / exec / rm  -->  one microVM per step
```

## Models

| Use | Default model id |
|---|---|
| Planning, patching, tool calls | `glm-5.3` |
| Log summaries | `deepseek-v4.1-flash-1017` |

Both ids come from Vultr's public model list. **Re-check them against `https://api.vultrinference.com/v1/models` after the hackathon kickoff**, and confirm that tool calls work, before a real run. The list shows `tools` for both models but no `tool_choice`, so the client never sends `tool_choice`.

`pqproof/inference.py` calls `POST /v1/chat/completions` with `Authorization: Bearer` and retries HTTP 429 and 5xx with backoff, honouring `Retry-After`. It does not trust `tool_calls`, because a prompt injection in the target repo can steer the model: a call to a tool the request did not declare, or with arguments that are not a JSON object, repeat a key, miss a required field, add an undeclared one or have the wrong type, comes back with an error on that call and no arguments. Any other malformed response raises `InferenceError`, and call ids are made unique. It reads the key from `VULTR_INFERENCE_API_KEY`; keep the key outside the repository. The client does not follow redirects, so the `Authorization` header cannot be carried to another host, and it redacts the key from any error text, including a server's own error message.

## Plan and allowlist

A human approves the model's plan (JSON; the schema is `PLAN_SCHEMA` in `pqproof/plan.py`). The approved plan compiles into an allowlist of exact command lines, repo-relative file paths and base images. An image must be a Docker Hub official image pinned by digest, such as `golang:1.25-bookworm@sha256:<64 hex>`; a tag alone is refused because the registry owner can move it, and so is any other registry. A command may use only `make` (targets), `go` (`build`, `test` or `vet` on packages, a few fixed flags, and `-o=` a path inside the work tree), `nginx` (`-t`, `-c` with absolute config paths) and PQ-Proof's own `tls_probe` (fixed subcommands, loopback addresses and absolute paths only); every other program is refused, and so is any argument outside those shapes, such as `go build -toolexec`, `make --eval` or `nginx -g`. That limits what the model can ask for. It does not make the repository's own code safe: `make test` runs the repo's Makefile recipes with `/bin/sh` and `go test` runs its test code. That code is untrusted and runs only inside a microVM with egress denied, which is the real boundary (see Containment). The plan has no field for egress hosts because sandboxes get none. The allowlist does not read file contents: a change like `InsecureSkipVerify: true` inside an approved file is caught by a deterministic TLS-weakening check on the diff (*planned*).

## Inventory (CBOM)

`pqproof/scan.py` lists the places in a repo snapshot that decide its TLS key exchange, and the signatures it uses, as rows of a cryptography bill of materials (CBOM): path, line, algorithm, NIST IR 8547 status, whether the row keeps the service off `X25519MLKEM768`, and whether PQ-Proof patches it. It reads nginx `ssl_ecdh_curve`, Go `tls.Config` `CurvePreferences`, the `go` line of `go.mod` (below 1.24, Go keeps its pre-1.24 default key exchanges, `GODEBUG=tlsmlkem=0`, even after a curve pin is gone), the runtime stage of each Dockerfile (Debian bookworm ships OpenSSL 3.0, which has no ML-KEM; trixie ships 3.5) and RSA or ECDSA JWT signing methods. Signatures are reported and never patched. The scanner only reads: it skips `vendor/`, tests and `.git`, does not follow symlinks, and reads at most 1 MiB of a file. Its rows are a static guess; the probe decides.

## Proof

Success is decided by a handshake, not by a model. The client is `tls_probe` (`probe/tls_probe.go`), a small static Go program (standard library only, `CGO_ENABLED=0`) that PQ-Proof builds offline inside a microVM from a pinned `golang:1.27-bookworm` image and copies into every microVM it tests. A client from the target's own image would not do: orders-edge's image ships OpenSSL 3.0, which does not even know the name `X25519MLKEM768`, so a failed handshake would say nothing about the server. Before any server is judged, the same probe must negotiate `X25519MLKEM768` with its own reference server inside the same microVM (the positive control); if it cannot, there is no verdict. Then it connects to each server twice: once offering only `X25519MLKEM768` (success means the server negotiated hybrid ML-KEM) and once offering only classical groups (`X25519,P-256`, a client from before ML-KEM, which must still connect). The receipt records the probe's name, version and SHA-256 and the SHA-256 of its source. `pqproof/prove.py` also reads `openssl s_client` output for cross-checks; note that a classical handshake there prints no `Negotiated TLS1.3 group` line, only `Peer Temp Key: X25519, 253 bits`, and a failed one prints `Negotiated TLS1.3 group NID: 0`.

Base images are pinned by OCI index digest (`pqproof/images.py`), so one pin works on an arm64 Mac and on the amd64 VX1 host. Measured with msb 0.7.13: `msb pull` resolves an index digest to the host's platform, and `msb image inspect` then reports the platform manifest digest, which is what a receipt records.

## Containment

Each step runs in a fresh Microsandbox microVM with its own kernel. A step can copy files in (`msb copy`), run several allowlisted commands, start a server as a background job (`msb exec -d`) and copy one built file out; a copied-out file that is not a regular file (a symlink the guest planted, say) is deleted and refused. The control plane creates it with `--cpus`, `--memory` and `--max-duration` (defaults: 1 vCPU, 1 GiB, 120 s), labels it `app=pqproof`, and lets it use only images the control plane has already pulled (`--pull never`). The runner itself refuses any image or command line that the step's approved allowlist does not hold, and passes the image after `--` so it is never read as an `msb` option. The host also times `msb exec` and always runs `msb rm --force` afterwards. A reaper removes any labelled sandbox past its lifetime at startup and every minute, so a crashed control plane leaves nothing running. Every `msb` command line is kept for the receipt, and so is each step's output, cut to the first and last 512 KiB of each stream with the full stream's byte count and SHA-256, so a step that floods its output cannot fill the control plane's memory. `msb` runs with only `PATH`, `HOME` and its own `MSB_*` settings in its environment, because it passes that environment on to each sandbox's VMM process; the inference API key is never in it.

Egress is denied for every step, the build included. DNS goes only to a resolver on the host that records the queries it receives, over UDP and over TCP, and answers NXDOMAIN instead of forwarding them. TCP to `203.0.113.0/24`, a documentation range that is never routed, goes through Microsandbox's `--proxy` to a host sinkhole that records the destination and the bytes; that is how the demo shows a planted test hook's canary. Everything else, including the host and the control plane API, is dropped by Microsandbox's network policy, and a dead sinkhole does not open a direct route. The demo hook uses plain HTTP so the sinkhole can read the canary; HTTPS attempts are recorded as encrypted bytes only. The sinkhole is bounded too: it serves at most 16 connections at a time and keeps at most 1,000 events between collections (the rest are counted, and canary ids are still collected), and `msb` holds each guest to 32 TCP connections and 200 outbound packets per second. Attempts that Microsandbox's policy drops before they reach the sinkhole, such as a direct connection to `1.1.1.1`, are blocked but not counted, so a receipt can list only the attempts that reached the sinkhole.

Integration tests (`tests/test_sandbox.py`, `tests/test_egress.py`) run real microVMs whenever `msb` is installed; set `PQPROOF_MSB_TESTS=0` to skip them and `PQPROOF_WALL_S=120` to check the full wall clock. They pin `alpine` by the digest of the copy in the local cache, so they use the network only when that cache is empty. So far they have run on macOS (Apple Silicon) with msb 0.7.13; they still have to be run on the Vultr VX1 host.

## Development

```sh
python3 -m unittest discover -s tests -v
```

Unit tests need no network and no API key. If `msb` is installed, this command also runs the integration tests (real microVMs, and `msb pull alpine` when the image is not cached yet); `PQPROOF_MSB_TESTS=0 python3 -m unittest discover -s tests -v` runs the unit tests alone.

## License

[MIT](LICENSE)
