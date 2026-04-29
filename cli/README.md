# vid-transfer CLI

C implementation of the validator-identity transfer client. Single static
binary, libsodium for crypto, libcurl for HTTP. Runs on Linux and macOS.

## Build

```bash
# macOS
brew install libsodium curl pkg-config
make

# Debian/Ubuntu
sudo apt-get install libsodium-dev libcurl4-openssl-dev pkg-config build-essential
make

# RHEL/Alma/Rocky
sudo dnf install libsodium-devel libcurl-devel pkgconf gcc make
make
```

The default `make` target produces `build/vid-transfer`. Use
`make release` for a stripped, `-O3` build, or `make debug` for an
ASan/UBSan build (requires `clang` or recent `gcc`).

`sudo make install` copies the binary to `/usr/local/bin/vid-transfer`.

## Subcommands

| Command | Purpose |
|---|---|
| `init` | Write `~/.vid-transfer/config.toml` with defaults. |
| `doctor` | Check libsodium init, sealed-box round-trip, relay reachability, RPC reachability, optional keypair parse. |
| `status` | Inspect a `validator-keypair.json`: derive pubkey, read vote account, summarise the leader schedule, refuse to proceed if a leader slot is imminent. |
| `receive` | Generate ephemeral X25519 keypair, register with the relay, print pairing code, long-poll for ciphertext, decrypt, write `validator-keypair.json` (and the tower file if present). |
| `send <CODE>` | Decode pairing code, fetch and verify recipient pubkey from the relay, run pre-flight, build the bundle, sealed-box encrypt, upload. |
| `swap-out` | Wrap `agave-validator -l <ledger> set-identity <unstaked>`. |
| `swap-in` | Wrap `agave-validator -l <ledger> set-identity --require-tower <real>`. |

## Important flags

- `--keypair PATH` — path to `validator-keypair.json` (send/status/swap).
- `--out PATH` — where receive writes the keypair (default `./received-validator-keypair.json`).
- `--ledger DIR` — used to find/write `tower-1_9-<id>.bin`.
- `--tower PATH` — explicit tower-file override.
- `--no-tower` — skip the tower (loud warning; risky).
- `--expected-pubkey <base58>` — pin the received identity; mismatch aborts.
- `--relay URL` — override the relay (also `$VIDX_RELAY`).
- `--rpc URL` / `--cluster mainnet|testnet|devnet`.
- `--wait SECONDS` — long-poll timeout for `receive` (default 600).
- `--force` — overwrite existing output files / no-confirm on swap.
- `--skip-preflight` — bypass the leader-schedule check (dangerous).
- `--allow-loose-perms` — accept `validator-keypair.json` with mode > 0600.
- `--insecure-tls` — disable TLS cert verification (testing only).
- `-v` / `-vv` — more logs / debug logs.

## Source layout

```
src/
├── main.c              CLI argument parsing and dispatch.
├── util.c/.h           Logging, file I/O, hex, line-prompt, sleep.
├── secure_mem.c/.h     mlock'd allocation, signal handler, zeroize.
├── crypto.c/.h         libsodium wrappers (sealed box, blake2b, ed25519).
├── base58.c/.h         Solana pubkey codec.
├── keypair.c/.h        validator-keypair.json parser/writer.
├── pairing.c/.h        BIP39 → 6-word pairing-code codec.
├── bip39_wordlist.c/.h Embedded BIP39 English list (binary search).
├── relay.c/.h          libcurl client for the relay HTTP API.
├── solana_rpc.c/.h     Minimal JSON-RPC client (epoch info, vote
│                       accounts, leader schedule, version).
├── tower.c/.h          Tower-file locate/read/write.
├── bundle.c/.h         Wire-format codec for the encrypted payload.
└── commands/
    ├── cmd_init.c
    ├── cmd_doctor.c
    ├── cmd_status.c
    ├── cmd_send.c
    ├── cmd_receive.c
    └── cmd_swap.c
```

## Memory hygiene

Any buffer that may hold key material is allocated via `secure_alloc()`,
which wraps `sodium_malloc` (`mlock` + guard pages). On any exit path —
success, error return, or signal — those buffers are wiped and freed.
A signal handler registered at startup wipes the handful of live-secret
buffers tracked in `secure_mem.c` before re-raising, so even a Ctrl-C
in the middle of a transfer leaves no trace.

## Build matrix

The Makefile turns on `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`,
`-Wall -Wextra -Wpedantic -Wshadow`. On Linux it adds `-pie`,
`-Wl,-z,now`, `-Wl,-z,relro`. `make debug` adds AddressSanitizer and
UndefinedBehaviorSanitizer.

## Tests

A pure-CLI smoke test that exercises the full send/receive loop against
a local relay lives at `../scripts/e2e.sh` (relay startup, keypair
generation, pairing-code parse, bytes-equal verification). See
[../docs/DEMO.md](../docs/DEMO.md) for the full demo flow.
