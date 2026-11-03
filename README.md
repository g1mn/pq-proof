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

`pqproof/inference.py` calls `POST /v1/chat/completions` with `Authorization: Bearer`, parses `tool_calls` (arguments that are not a JSON object come back as an error on that call instead of an exception), and retries HTTP 429 and 5xx with backoff, honouring `Retry-After`. It reads the key from `VULTR_INFERENCE_API_KEY`; keep the key outside the repository.

## Plan and allowlist

A human approves the model's plan (JSON; the schema is `PLAN_SCHEMA` in `pqproof/plan.py`). The approved plan compiles into an allowlist of exact command lines, repo-relative file paths and pinned base images. Shells, `env`, network tools and inline code such as `python -c` are refused, and the plan has no field for egress hosts because sandboxes get none. The allowlist does not read file contents: a change like `InsecureSkipVerify: true` inside an approved file is caught by a deterministic TLS-weakening check on the diff (*planned*).

## Containment

Each step runs in a fresh Microsandbox microVM with its own kernel. The control plane creates it with `--cpus`, `--memory` and `--max-duration` (defaults: 1 vCPU, 1 GiB, 120 s), labels it `app=pqproof`, and lets it use only images the control plane has already pulled (`--pull never`). The host also times `msb exec` and always runs `msb rm --force` afterwards. A reaper removes any labelled sandbox past its lifetime at startup and every minute, so a crashed control plane leaves nothing running. Every `msb` command line is kept for the receipt.

## Development

```sh
python3 -m unittest discover -s tests -v
```

Unit tests need no network and no API key.

## License

[MIT](LICENSE)
