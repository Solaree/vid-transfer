# Product brief

**vid-transfer** is a CLI plus a stateless relay service that securely
moves a Solana validator's identity (`validator-keypair.json` + tower
file) between hosts in a single command on each side.

## The problem

Migrating a validator is the most slashing-prone routine operation in
Solana ops. Operators today either `scp` the key over SSH (no tower
handoff, no leader-schedule check), stash it in a long-lived secret
store (extra attack surface), or hand-copy the JSON (no.). All of these
leave a window where the same identity could sign on two machines —
which slashes the stake.

## The product

The receiver runs `vid-transfer receive` and the screen displays a
6-word pairing code (BIP39 words encoding the first 8 bytes of
`blake2b-512` of an ephemeral X25519 public key). The sender types those
6 words; the CLI fetches the recipient's public key from the relay,
**re-derives the prefix locally, and refuses to upload if it doesn't
match**. The bundle (key + tower + metadata) is sealed-box encrypted
client-side, uploaded once, drained once, and wiped. The relay sees
only ciphertext and a public key.

The CLI is C with libsodium for crypto and mlock + guard pages for key
buffers. The relay is a 200-line Fastify service with no database; it
TTLs sessions in 5 minutes and refuses second uploads or second drains.

## Target user

A Solana validator operator on mainnet, testnet, or a private cluster
who needs to migrate a validator identity to a new host — hardware
refresh, datacenter move, post-incident rebuild, or rehearsing a
hot-failover — and who wants the migration to be auditable end-to-end
in a single sitting.

## Why it wins

- **Execution & completeness:** real validator integration (`set-identity --require-tower`),
  leader-schedule pre-flight, atomic 0600 file writes, signal-safe key
  wipe, two passing test suites (positive flow + adversarial).
- **Security:** sealed-box X25519 / XSalsa20-Poly1305, blake2b-binding
  pairing code that makes a hostile relay non-fatal, mlock'd memory,
  one-shot session model with TTL.
- **UX:** 6 words, two commands, one paste. No configuration. No SSH.
- **Live deploy:** the relay is a single 256 MB Fly.io / Railway / Docker
  container with a healthchecked landing page; deploy is one command.
