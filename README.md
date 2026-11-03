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

A human approves the model's plan (JSON; the schema is `PLAN_SCHEMA` in `pqproof/plan.py`). The approved plan compiles into an allowlist of exact command lines, repo-relative file paths and base images. An image must be a Docker Hub official image pinned by digest, such as `golang:1.25-bookworm@sha256:<64 hex>`; a tag alone is refused because the registry owner can move it, and so is any other registry. A command may use only `make` (targets), `go` (`build`, `test` or `vet` on packages, a few fixed flags, and `-o=` a path inside the work tree), `nginx` (`-t`, `-c` with absolute config paths) and PQ-Proof's own `tls_probe` (fixed subcommands, loopback addresses and absolute paths only). A plan may also run, by name and with `-flag=value` arguments only, a program it builds itself with `go build -o=out/NAME` (the server it is about to prove; a name like `sh` or `curl` is refused), and it must list at least one loopback address (`127.0.0.1:PORT`, never the probe's own `127.0.0.1:4433`) to probe inside the prove microVM; the approval screen shows each one, and a run that probes nothing is a failure, not a pass. Every other program is refused, and so is any argument outside those shapes, such as `go build -toolexec`, `make --eval` or `nginx -g`. That limits what the model can ask for. It does not make the repository's own code safe: `make test` runs the repo's Makefile recipes with `/bin/sh` and `go test` runs its test code. That code is untrusted and runs only inside a microVM with egress denied, which is the real boundary (see Containment). The plan has no field for egress hosts because sandboxes get none. The allowlist does not read file contents: a change like `InsecureSkipVerify: true` inside an approved file is caught by a deterministic TLS-weakening check on the diff (*planned*).

## Patch loop

`pqproof/loop.py` asks the model for edits through one declared tool, `propose_edits` (`{path, old, new}`, where `old` must occur exactly once), applies them to a fresh copy of the original snapshot, builds inside microVMs, and on failure sends the failing step's raw output (its last 8,000 characters) back to the model. It stops after 3 attempts. The edit applier trusts nothing in the snapshot: the path must be in the approved plan, `os.path.realpath` of the target must be the target itself inside the snapshot (a symlink anywhere on the path is refused, even one that points back inside), and the file is opened one directory at a time with `O_NOFOLLOW`, so a symlink that appears after that check still cannot be followed. An edit that is refused counts as a failed attempt and is not built.

Images the model names (`nginx:1.30-trixie`) are resolved before approval: the control plane runs `msb pull` and `msb image inspect` on the host and shows `nginx:1.30-trixie@sha256:<digest>` with its platform, and only that pinned reference goes into the allowlist. The digest is the host's platform manifest, so the VX1 host (amd64) shows a different digest than a Mac (arm64).

## Inventory (CBOM)

`pqproof/scan.py` lists the places in a repo snapshot that decide its TLS key exchange, and the signatures it uses, as rows of a cryptography bill of materials (CBOM): path, line, algorithm, NIST IR 8547 status, whether the row keeps the service off `X25519MLKEM768`, and whether PQ-Proof patches it. It reads nginx `ssl_ecdh_curve`, Go `tls.Config` `CurvePreferences`, the `go` line of `go.mod` (below 1.24, Go keeps its pre-1.24 default key exchanges, `GODEBUG=tlsmlkem=0`, even after a curve pin is gone), the runtime stage of each Dockerfile (Debian bookworm ships OpenSSL 3.0, which has no ML-KEM; trixie ships 3.5) and RSA or ECDSA JWT signing methods. Signatures are reported and never patched. The scanner only reads: it skips `vendor/`, tests and `.git`, does not follow symlinks, and reads at most 1 MiB of a file. Its rows are a static guess; the probe decides.

## Proof

Success is decided by a handshake, not by a model. The client is `tls_probe` (`probe/tls_probe.go`), a small static Go program (standard library only, `CGO_ENABLED=0`) that PQ-Proof builds offline inside a microVM from a pinned `golang:1.27-bookworm` image and copies into every microVM it tests. A client from the target's own image would not do: orders-edge's image ships OpenSSL 3.0, which does not even know the name `X25519MLKEM768`, so a failed handshake would say nothing about the server. Before any server is judged, the probe starts two reference servers of its own inside the same microVM, ahead of the repo's servers. Offering only `X25519MLKEM768`, it must negotiate `X25519MLKEM768` with the first (the positive control) and must fail against the second, which accepts only `X25519` (the negative control; a classical client must still reach it with `X25519`). If either control fails, the attempt fails with "proof invalid" and no server is judged: a probe that always reports hybrid, for instance one that code in the microVM swapped for a script, fails the negative control. The probe, its reference servers and the test certificate stay root-owned, while the repo's servers run as unprivileged users, one uid for the built programs and another for nginx (the control plane only creates nginx's pid file and cache directory for it), so code under test cannot replace the probe. The probe binary is also copied back out and hashed on the host before the controls and after the last handshake; a different hash makes the proof invalid. This still trusts the guest kernel: code that gained root inside the microVM through a kernel bug could forge a handshake. Running the probe in a separate microVM is not done yet. Then it connects to each server twice: once offering only `X25519MLKEM768` (success means the server negotiated hybrid ML-KEM) and once offering only classical groups (`X25519,P-256`, a client from before ML-KEM, which must still connect). The receipt records the probe's name, version and SHA-256 and the SHA-256 of its source. `pqproof/prove.py` also reads `openssl s_client` output for cross-checks; note that a classical handshake there prints no `Negotiated TLS1.3 group` line, only `Peer Temp Key: X25519, 253 bits`, and a failed one prints `Negotiated TLS1.3 group NID: 0`.

Base images are pinned by OCI index digest (`pqproof/images.py`), so one pin works on an arm64 Mac and on the amd64 VX1 host. Measured with msb 0.7.13: `msb pull` resolves an index digest to the host's platform, and `msb image inspect` then reports the platform manifest digest, which is what a receipt records.

## Containment

Each step runs in a fresh Microsandbox microVM with its own kernel. A step can copy files in (`msb copy`), run several allowlisted commands, start a server as a background job (`msb exec -d`) and copy one built file out; a copied-out file that is not a regular file (a symlink the guest planted, say) is deleted and refused. The control plane creates it with `--cpus`, `--memory` and `--max-duration` (defaults: 1 vCPU, 1 GiB, 120 s), labels it `app=pqproof`, and lets it use only images the control plane has already pulled (`--pull never`). The runner itself refuses any image or command line that the step's approved allowlist does not hold, and passes the image after `--` so it is never read as an `msb` option. The host also times `msb exec` and always runs `msb rm --force` afterwards. A reaper removes any labelled sandbox past its lifetime at startup and every minute, so a crashed control plane leaves nothing running. Every `msb` command line is kept for the receipt, and so is each step's output, cut to the first and last 512 KiB of each stream with the full stream's byte count and SHA-256, so a step that floods its output cannot fill the control plane's memory. `msb` runs with only `PATH`, `HOME` and its own `MSB_*` settings in its environment, because it passes that environment on to each sandbox's VMM process; the inference API key is never in it.

Egress is denied for every step, the build included. DNS goes only to a resolver on the host that records the queries it receives, over UDP and over TCP, and answers NXDOMAIN instead of forwarding them. TCP to `203.0.113.0/24`, a documentation range that is never routed, goes through Microsandbox's `--proxy` to a host sinkhole that records the destination and the bytes; that is how the demo shows a planted test hook's canary. Everything else, including the host and the control plane API, is dropped by Microsandbox's network policy, and a dead sinkhole does not open a direct route. The demo hook uses plain HTTP so the sinkhole can read the canary; HTTPS attempts are recorded as encrypted bytes only. The sinkhole is bounded too: it serves at most 16 connections at a time and keeps at most 1,000 events between collections (the rest are counted, and canary ids are still collected), and `msb` holds each guest to 32 TCP connections and 200 outbound packets per second. Attempts that Microsandbox's policy drops before they reach the sinkhole, such as a direct connection to `1.1.1.1`, are blocked but not counted, so a receipt can list only the attempts that reached the sinkhole.

Integration tests (`tests/test_sandbox.py`, `tests/test_egress.py`) run real microVMs whenever `msb` is installed; set `PQPROOF_MSB_TESTS=0` to skip them and `PQPROOF_WALL_S=120` to check the full wall clock. They pin `alpine` by the digest of the copy in the local cache, so they use the network only when that cache is empty. So far they have run on macOS (Apple Silicon) with msb 0.7.13; they still have to be run on the Vultr VX1 host.

## End-to-end run on orders-edge

`e2e/orders_edge.py` runs the whole pipeline on orders-edge (a separate fixture repository, not public yet), a small nginx + Go fixture with a classical-only TLS key exchange, a planted test hook and a prompt-injection line (`pqproof/pipeline.py` does the work):

1. Snapshot with `git clone --no-recurse-submodules` (the only non-`msb` commands on the host are `git clone` and `git rev-parse`), and the CBOM.
2. The plan's image tags are resolved to `name:tag@sha256:<digest>` and shown for approval.
3. Build: a microVM from the Dockerfile's build image runs `make test` and `go build` offline (vendored modules, `GOPROXY=off`); the binary comes out as one regular file. Prove: a microVM from the Dockerfile's runtime image runs `nginx -t`, starts the API and nginx as background jobs, passes the probe's positive control and probes both TLS ports. The Dockerfile itself is never built.
4. Baseline first, then the patch loop.

**The model is scripted in this run.** No Vultr Serverless Inference key was available yet, so `e2e/orders-edge-scripted-model.json` stands in for it: a plan and two attempts of fixed edits written by hand, and no inference call is made. Attempt 1 changes the nginx group list, the Go `CurvePreferences` and the `go` line but keeps the OpenSSL 3.0 runtime image on purpose; attempt 2 also moves the runtime image to `nginx:1.30-trixie`. The run shows containment, the build, the raw-error feedback and the proof, not model quality.

Measured on an M-series Mac with msb 0.7.13 (November 4, 2026), 75 s in all:

| | `127.0.0.1:8443` (nginx) | `127.0.0.1:9443` (Go API) |
|---|---|---|
| Baseline, hybrid-only client | `remote error: tls: handshake failure` | `remote error: tls: handshake failure` |
| Baseline, classical client | P-256 | P-256 |
| Attempt 1 | `nginx -t` fails: `group 'X25519MLKEM768' cannot be set` (OpenSSL 3.0); this raw error is the feedback | |
| Attempt 2, hybrid-only client | `X25519MLKEM768` | `X25519MLKEM768` |
| Attempt 2, classical client | X25519 | X25519 |

Every `make`, `go` and `nginx` command ran inside `msb exec` (0 on the host), the planted test hook's `CANARY-0001` landed in the sinkhole during `make test`, every microVM was removed, and the CBOM after the patch has no row that blocks hybrid key exchange (the RS256 JWT row stays: signatures are out of scope). The same probe binary built twice gave the same SHA-256.

```sh
python3 e2e/orders_edge.py --repo ../orders-edge --approve   # exit code 0 only if every check passes
```

## Development

```sh
python3 -m unittest discover -s tests -v
```

Unit tests need no network and no API key. `PQPROOF_E2E_REPO=../orders-edge` also runs the end-to-end test. If `msb` is installed, this command also runs the integration tests (real microVMs, and `msb pull alpine` when the image is not cached yet); `PQPROOF_MSB_TESTS=0 python3 -m unittest discover -s tests -v` runs the unit tests alone.

## Development note

Coding started 20 to 40 minutes before the official kickoff (16:00 UTC on November 3, after the start was moved back an hour), and the first commit came after it. The event page invites participants to "get a head start on your project" before the kickoff.

## License

[MIT](LICENSE)
