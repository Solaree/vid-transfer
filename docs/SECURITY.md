# Security model

`vid-transfer` is built around three goals, in priority order:

1. **The validator's private key never appears in plaintext on a third
   party** — neither the relay, nor any intermediate proxy, nor any
   on-disk artifact other than `validator-keypair.json` on the operator's
   own machines.
2. **A compromised relay cannot read or substitute keys.** The worst it
   can do is deny service.
3. **The CLI never silently does the wrong thing.** It refuses
   slashing-prone operations rather than warning about them.

## Threat model

We assume the adversary may:

- Operate or compromise the relay (read all traffic, replace responses,
  forge sessions).
- Sit on the network path between either operator host and the relay
  (TLS-stripping, fingerprinted timing, inserted bytes).
- Have read access to one operator host's filesystem *after* the
  transfer completed (forensics, snapshots).
- Run another validator with similar identity bytes, or attempt to grind
  a public key whose blake2b prefix collides with the operator's.

We do **not** defend against:

- A fully compromised operator host *during* the transfer (root on the
  sending machine sees the key already).
- Side channels on the validator host — `vid-transfer` does what
  `solana-keygen` already does on the same host (read the JSON file).
- Lost/forgotten ledger directories that already contain the key.

## Cryptographic primitives

| Purpose | Primitive | libsodium API | Notes |
|---|---|---|---|
| Encrypt-to-recipient | X25519 + XSalsa20-Poly1305 | `crypto_box_seal` | Anonymous sealed box; sender does not need a long-lived key. |
| Pairing-code prefix | BLAKE2b-512 truncated to 8 bytes | `crypto_generichash(out=64)` | Truncating a fixed-length hash is required so the relay (Node OpenSSL) can verify with `createHash("blake2b512")`. |
| Identity self-check | Ed25519 `sk → pk` | `crypto_sign_ed25519_sk_to_pk` | Verifies the embedded pk in the keypair file is consistent with the seed. |
| RNG | `randombytes_buf` | libsodium CSPRNG | Used to generate the receiver's ephemeral X25519 key. |

The pairing code is `BLAKE2b-512(recipient_pubkey)[0..8]` rendered as
6 BIP39 English words (66 bits encoded; high 2 bits are zero and act as
a structural sanity check during decode).

## Why a "sealed box"?

A sealed box (libsodium's `crypto_box_seal`) generates a **fresh
ephemeral X25519 keypair on every send**. The recipient's static public
key plus the ephemeral public key are combined into a shared secret that
authenticates and encrypts the bundle in a single step. Two consequences:

- The sender does not need long-lived asymmetric material — there is no
  "sender identity" to protect or rotate.
- An attacker who later compromises the recipient's static private key
  *after* the session is over still cannot decrypt the historic
  ciphertext blob, because the relay deletes ciphertext on first delivery
  and on TTL expiry — there is nothing to replay against.

## Pairing protocol, step by step

```
RECV: sk_eph, pk_eph  ← X25519 keygen        # in mlock'd memory
RECV: prefix          ← blake2b(pk_eph)[:8]
RECV: code            ← bip39(prefix)        # 6 words
RECV: POST /v1/sessions { prefix, recipientPubkey: pk_eph, version: 1 }

operator reads `code` and types it on the SENDER:

SEND: prefix'         ← bip39_decode(code)
SEND: GET /v1/sessions/<prefix'>             # → { recipientPubkey: pk' }
SEND: ASSERT blake2b(pk')[:8] == prefix'     # ★ key step
       └─ if false: ABORT — the relay is malicious
SEND: bundle ← {validator_keypair, expected_pk, tower, hostname, timestamp}
SEND: ct     ← seal_box(bundle, pk')
SEND: PUT /v1/sessions/<prefix>/ciphertext   # one-shot

RECV: GET /v1/sessions/<prefix>/ciphertext?wait=1   # long-poll, single use
RECV: bundle ← seal_box_open(ct, pk_eph, sk_eph)
RECV: ASSERT bundle.expected_pk == ed25519_sk_to_pk(bundle.keypair)
RECV: ASSERT (--expected-pubkey == base58(bundle.expected_pk))    # if pinned
RECV: write validator-keypair.json (0600, atomic rename)
RECV: write tower file (0600, atomic rename) if present
```

The "★ key step" is what makes the relay untrusted. Even if the relay
substitutes a public key it controls and lies about it on the GET, the
sender refuses to upload because `blake2b(pk)[:8] ≠ prefix`. The operator
typed the prefix; the relay cannot retroactively choose it.

## Memory hygiene

The CLI uses `sodium_malloc` for any buffer that can hold key material:

- guard pages around the allocation,
- `mlock` so the buffer never reaches swap,
- `sodium_memzero` on free or on error path,
- a global signal handler (`SIGINT/SIGTERM/SIGHUP`) wipes all registered
  buffers before re-raising the signal — so even a `^C` mid-flow doesn't
  leave the key sitting in heap pages.

Plaintext bundles are also held in `sodium_malloc` buffers, and the
ciphertext buffer is wiped immediately after upload/download.

## Filesystem hygiene

- Refuses to read a `validator-keypair.json` whose mode includes any
  group/other access bits, unless `--allow-loose-perms` is passed.
- Refuses to follow symlinks for the keypair file.
- Output files are written with mode `0600`, atomically (`tmp` +
  `rename`).
- Refuses to overwrite the destination by default; require `--force`.

## Network hygiene

- TLS verification is on by default; `--insecure-tls` exists for testing
  with self-signed deploys but is loud about it.
- Only `https,http` schemes are allowed; redirects must be `https` only.
- Request bodies and per-call timeouts are bounded.
- The relay enforces a 5-minute session TTL, a per-IP rate limit, and a
  hard ceiling on ciphertext size (320 KiB).

## What would actually break this?

The smallest-step compromises that would let an attacker exfiltrate a
real validator key:

1. **The operator copy/pastes the wrong code.** Then either the session
   doesn't exist, or it does and the prefix verification trips. The CLI
   refuses to upload.
2. **The relay substitutes a public key with a colliding 8-byte prefix.**
   Birthday cost is ~2⁶⁴ work. The slot expires in 5 minutes.
3. **The operator runs `--insecure-tls` on a hostile network.** TLS
   verification turns off; the relay can MITM the prefix-mismatch check
   too. Don't do this in production. The CLI prints a loud warning.
4. **An attacker gets root on the receiving host within the same
   minute.** Then they have the key anyway after `set-identity`. Out of
   scope for the transfer protocol.

There's no "transfer-time-only" attack we are aware of that survives
both prefix verification and sealed-box authentication.

## Reporting issues

`security@<your-domain>` (set in your fork). Please include reproduction
steps; we'll publish coordinated fixes on the GitHub releases page.
