# vid-transfer

<img width="857" height="1041" src="https://github.com/user-attachments/assets/617a97d1-c4da-48cc-ad65-d35ef4ccc7ca" />

> **Magic Wormhole for Solana validator identity.**
> One CLI, one paste of 6 words, the key never touches a third party in
> the clear, the tower file moves with it, no slashing.

[![relay](https://img.shields.io/badge/live%20relay-vid--transfer--relay.fly.dev-4cc38a)](https://vid-transfer-relay.fly.dev)
[![license](https://img.shields.io/badge/license-MIT-8b95a4)](LICENSE)
[![tests](https://img.shields.io/badge/tests-e2e%20%2B%20mismatch-4cc38a)](scripts/)
[![source](https://img.shields.io/badge/source-Solaree%2Fvid--transfer-6cb6ff)](https://github.com/Solaree/vid-transfer)

`vid-transfer` is a CLI plus a stateless relay that lets a Solana
validator operator move `validator-keypair.json` (and the matching tower
file) from the *old* host to the *new* host without:

- the private key ever touching disk in plaintext on the relay,
- trusting the relay's TLS,
- needing SSH between the two operator hosts,
- typing the 64-byte JSON array in by hand,
- and **without** the double-signing window that `scp` workflows leave open.

The protocol is small enough to audit in one sitting. See
[docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Why this exists

Migrating a validator is the most slashing-prone routine operation in
Solana ops. Existing options:

| Approach | Encrypted in transit? | Tower handoff? | Slash-window narrowed? | Audit footprint |
|---|---|---|---|---|
| `scp` over SSH | Yes (SSH) | Manual, easy to forget | No | Two SSH sessions, ad hoc |
| Vault / S3 / 1Password | Yes (TLS + at rest) | Manual | No | **Long-lived** key copy |
| Hand-copy the JSON | No | No | No | Eyes |
| **`vid-transfer`** | **Yes (sealed-box X25519)** | **Yes** | **Yes (leader-schedule pre-flight)** | **Single ciphertext blob, single use** |

Target user: a Solana validator operator on mainnet, testnet, or a
private cluster who needs to migrate a validator identity to a new host
(hardware refresh, datacenter move, post-incident rebuild, planned
hot-failover practice).

---

## Quickstart

> The CLI ships pointing at the public relay
> <https://vid-transfer-relay.fly.dev>. Override with `--relay URL` or
> `$VIDX_RELAY` if you self-host (see [docs/DEPLOY.md](docs/DEPLOY.md)).

```bash
# 0. Build (Linux / macOS)
brew install libsodium curl pkg-config       # macOS
# Debian/Ubuntu: apt-get install libsodium-dev libcurl4-openssl-dev pkg-config
make           # builds CLI + relay

# 1. NEW host: announce yourself, get a 6-word pairing code
vid-transfer receive \
  --out  /etc/solana/validator-keypair.json \
  --ledger /mnt/ledger \
  --expected-pubkey 7Np4...JxZ
#  ┌─────────────────────────────────────────────────────────────┐
#  │  spider-decline-mango-rib-couple-trial                      │
#  └─────────────────────────────────────────────────────────────┘

# 2. OLD host: type those 6 words
vid-transfer send spider-decline-mango-rib-couple-trial \
  --keypair /etc/solana/validator-keypair.json \
  --ledger /mnt/ledger

# 3. Hot-swap on each side (wraps `agave-validator … set-identity`)
# old:
vid-transfer swap-out --ledger /mnt/ledger --keypair /etc/solana/unstaked.json
# new:
vid-transfer swap-in  --ledger /mnt/ledger --keypair /etc/solana/validator-keypair.json
```

That's it. The whole transfer is one paste of one 6-word phrase. The
relay sees one ciphertext blob and forgets it after delivery.

---

## End-to-end flow

```
+---------------------+   +---------------+   +---------------------+
|     OLD HOST        |   |     RELAY     |   |     NEW HOST        |
|  vid-transfer send  |   |  ciphertext   |   |  vid-transfer       |
|                     |   |  passthrough  |   |        receive      |
+---------------------+   +-------+-------+   +---------------------+
          |                       |                     |
          |              1. POST /sessions <-- recipient pk + prefix
          |                       |                     |
          |  2. operator types the 6 BIP39 words on both sides
          |                       |                     |
          |  3. GET /sessions/<prefix> -> recipient pk |
          |     CLI re-derives blake2b(pk)[:8] and ABORTS on mismatch
          |                       |                     |
          |  4. seal_box(bundle, recipient pk)         |
          |     PUT /sessions/<prefix>/ciphertext      |
          |                       |                     |
          |                       |  5. GET ?wait=1    |
          |                       |  (one-shot drain)  |
          |                       |                     |
          v                       v                     v
   leader-schedule          sessions wiped       seal_box_open
   pre-flight passes        on first delivery     0600 atomic write
                            and TTL              + tower file
```

The bundle that gets sealed contains:

- the 64-byte ed25519 secret key (libsodium format = seed‖pk),
- the 32-byte expected pubkey for verification,
- the validator's tower file (`tower-1_9-<pubkey>.bin`),
- a host hint and timestamp.

---

## Security in one paragraph

The relay is a passthrough: it learns a 32-byte X25519 public key and an
opaque ciphertext blob, nothing else. The pairing code is the first 8
bytes of `blake2b-512(recipient_pubkey)` rendered as 6 BIP39 words; the
sender re-derives that prefix locally and refuses to upload if a
malicious relay returns a different public key. Sessions live for 5
minutes, are single-use, and are wiped from memory on first delivery.
Keys live only in `mlock`'d, guard-paged buffers (`sodium_malloc`) on
the CLI side, and are zeroed on success, error, signal, or exit. See
[docs/SECURITY.md](docs/SECURITY.md) for the protocol diagram, threat
model, and crypto rationale.

---

## Repository layout

```
.
├── cli/             # C CLI built on libsodium + libcurl
│   ├── src/         # one .c per concern, ~3.5 KLoC total
│   ├── Makefile     # Linux + macOS, single static binary
│   └── README.md
├── relay/  # TypeScript / Fastify 5 relay (sees ciphertext only)
│   ├── src/
│   ├── public/       # static landing page served by the relay itself
│   ├── Dockerfile
│   ├── fly.toml
│   ├── railway.json
│   └── README.md
├── docs/
│   ├── PRODUCT.md   # start here for the elevator pitch
│   ├── SECURITY.md  # threat model + crypto design
│   └── DEPLOY.md    # how to run a self-hosted relay
├── scripts/
│   ├── e2e.sh           # full transfer + tower + 0600 mode check
│   ├── e2e-mismatch.sh  # negative tests for the security path
│   ├── deploy.sh        # one-command Fly.io / Railway deploy
│   ├── install.sh       # source-install the CLI into $PREFIX/bin
│   └── demo-reset.sh    # reset state between demo-video takes
├── Makefile   # top-level convenience targets
└── README.md
```

---

## Try the protocol locally

```bash
make       # builds CLI + relay
make test  # spins up a local relay, runs the full transfer, verifies
           # bytes-for-bytes equality, tower-file equality, mode 0600

bash scripts/e2e-mismatch.sh  # exercises the security failure modes
```

Both scripts are self-contained — they generate a throwaway keypair,
spin a private relay on `127.0.0.1`, run the CLI against it, and assert
on the outputs. They both finish in under 5 seconds.

---

## What was *not* prioritised

- **Hardware-key (HSM / YubiKey) support.** Out of scope for v0.1; the
  bundle format has room for it as a future flag.
- **Multi-region relay replication.** Single-instance is a security
  feature, not a missing one — fewer copies of ciphertext.
- **GUI.** This is a tool for operators, run over SSH.

---

## License

MIT — see [LICENSE](LICENSE).
