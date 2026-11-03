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

## Development

```sh
python3 -m unittest discover -s tests -v
```

Unit tests need no network and no API key.

## License

[MIT](LICENSE)
