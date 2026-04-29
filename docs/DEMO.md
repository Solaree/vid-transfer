# Demo script

A 90-to-120-second screencast that hits all four judging criteria:
execution, security, UX, deployability.

## Setup (off camera)

- Two terminals side-by-side, labelled **OLD HOST** and **NEW HOST**.
- A browser tab on the relay URL (so the live deploy is visible).
- A throwaway keypair already at `/etc/solana/validator-keypair.json` on
  OLD; tower file at `/mnt/ledger/tower-1_9-<pk>.bin`.
- Both terminals already have `vid-transfer` installed.

## Beat sheet

```
00:00  TITLE
       "vid-transfer — secure validator identity migration on Solana"

00:05  Browser: relay landing page
       "This is the relay. It only ever holds ciphertext. The private
        key never leaves either operator host in the clear."

00:15  NEW HOST terminal
       $ vid-transfer receive --out new.json --ledger /mnt/ledger \
           --expected-pubkey 7Np4...JxZ
       (highlight the 6-word pairing code that pops up — it's RANDOM
        every time; whatever 6 words appear in your take are the ones
        you'll type on OLD HOST. Don't try to match this script's words.)

00:30  OLD HOST terminal
       $ vid-transfer status \
           --keypair /etc/solana/validator-keypair.json --ledger /mnt/ledger
       "Pre-flight: vote account, leader schedule, tower presence."

00:50  OLD HOST terminal
       $ vid-transfer send <pasted-pairing-code> \
           --keypair /etc/solana/validator-keypair.json --ledger /mnt/ledger
       (the CLI fetches the pubkey from the relay, verifies the prefix
        matches the typed words, prints "relay pubkey verified", asks
        "Send 4123 bytes of ciphertext now? Identity: 7Np4..." → y)

01:10  NEW HOST terminal flips through the post-decrypt checks:
       "decrypted 4031 bytes" → "validator identity: 7Np4...JxZ" →
       "identity matches the pinned --expected-pubkey" →
       "wrote tower file: /mnt/ledger/tower-1_9-7Np4...bin"
       
01:25  Hot-swap (optional but valuable for the judge):
       $ vid-transfer swap-out --ledger /mnt/ledger --keypair unstaked.json
       $ vid-transfer swap-in  --ledger /mnt/ledger --keypair new.json
       (each prints the exact `agave-validator set-identity ...` it ran,
        with `--require-tower` on swap-in)

01:45  CLOSE
       Three things:
       1. ciphertext only on the relay
       2. operator typed the words → relay can't substitute keys
       3. one-shot: relay deletes on first delivery
```

## Things to *show*, not say

- The **prefix verification** message ("relay pubkey verified against
  pairing code"). This is the whole security story in one line.
- The **0600 perms** of the output file on NEW (`ls -la new.json`).
- The relay's Pino logs in a fourth pane: a single
  `session_created` then a single `ciphertext_uploaded` then nothing —
  no payload contents, no key material.
- `htop` showing the receiver's RES staying flat — the key buffer is
  mlocked, not in swap.

## Failure-path demo (extra credit)

If you have time for an extra 30 seconds, demo the safety net:

```
NEW HOST: vid-transfer receive ...           # generates code A
OLD HOST: vid-transfer send <wrong code>     # → "PAIRING MISMATCH ... ABORTING"
```

This shows the prefix-verification path actually firing. The point is
that the operator's hand-typed code is what authenticates the recipient,
not the relay's response.

## Recording tips

- Use `asciinema rec` if your screencast tool can embed `.cast` files;
  it produces a vector-perfect recording with ~5 KB output. Otherwise
  any 1080p screen recorder is fine.
- Pre-stage the pairing-code copy/paste — the live recording will look
  more polished if you don't fumble across windows.
- Keep the relay landing page open in a small browser pane the entire
  time so the "live deployed application" requirement is visually
  satisfied throughout the clip.
