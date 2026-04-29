#!/usr/bin/env bash
#
# End-to-end smoke test for vid-transfer.
#
# Starts a local relay, generates a throwaway validator keypair (and an
# optional fake tower file), runs receiver in the background to capture
# the pairing code, runs sender, then verifies that the file delivered to
# the receiver decodes to the same 64-byte ed25519 secret key.
#
# Requires: node ≥20, the CLI built at cli/build/vid-transfer, and either
# `solana-keygen` or `node` (to synthesize a keypair).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/cli/build/vid-transfer"
RELAY_DIR="$ROOT/relay"
PORT="${PORT:-8181}"
TMPDIR="$(mktemp -d -t vidx-e2e.XXXXXX)"
trap 'echo; echo "[cleanup] $TMPDIR"; rm -rf "$TMPDIR"; kill ${RELAY_PID:-0} 2>/dev/null || true' EXIT

if [ ! -x "$CLI" ]; then
  echo "[!] $CLI not found — run 'make' in cli/ first." >&2
  exit 1
fi
if [ ! -d "$RELAY_DIR/dist" ]; then
  echo "[+] building relay…"
  (cd "$RELAY_DIR" && npm install --silent && npm run build --silent >/dev/null)
fi

KP="$TMPDIR/sender.json"
RECV="$TMPDIR/received.json"
TOWER="$TMPDIR/tower.bin"

if command -v solana-keygen >/dev/null 2>&1; then
  solana-keygen new --silent --no-bip39-passphrase --outfile "$KP" >/dev/null
else
  node -e '
    const c = require("crypto"); const fs = require("fs");
    const { publicKey, privateKey } = c.generateKeyPairSync("ed25519");
    const sk = privateKey.export({ format: "der", type: "pkcs8" });
    const seed = sk.subarray(sk.length - 32);                       // last 32 bytes = seed
    const pk = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const lib = Buffer.concat([seed, pk]);                          // libsodium SK = seed||pk
    fs.writeFileSync(process.argv[1], JSON.stringify(Array.from(lib)));
  ' "$KP"
fi
chmod 600 "$KP"

# Synthesize a 4 KiB fake tower file so we exercise the tower path too.
head -c 4096 /dev/urandom > "$TOWER"

echo "[+] starting relay on http://127.0.0.1:$PORT"
( cd "$RELAY_DIR" && PORT="$PORT" LOG_LEVEL=warn node dist/index.js ) &
RELAY_PID=$!

# Wait for healthz (max ~5s).
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then break; fi
  sleep 0.5
done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "[!] relay never became healthy"; exit 1; }

RECV_LOG="$TMPDIR/recv.log"
SEND_LOG="$TMPDIR/send.log"

echo "[+] starting receiver"
"$CLI" receive \
  --relay "http://127.0.0.1:$PORT" \
  --insecure-tls \
  --out "$RECV" \
  --tower "$TOWER" \
  --wait 30 \
  --force >"$RECV_LOG" 2>&1 &
RECV_PID=$!

# Parse the pairing code (6 lowercase words joined by hyphens) from receiver output.
CODE=""
for i in $(seq 1 50); do
  CODE="$(grep -oE '[a-z]+(-[a-z]+){5}' "$RECV_LOG" | head -1 || true)"
  if [ -n "$CODE" ]; then break; fi
  sleep 0.1
done
if [ -z "$CODE" ]; then
  echo "[!] receiver never printed a pairing code:"
  cat "$RECV_LOG"
  exit 1
fi
echo "[+] pairing code: $CODE"

echo "[+] running sender"
echo y | "$CLI" send "$CODE" \
  --relay "http://127.0.0.1:$PORT" \
  --insecure-tls \
  --keypair "$KP" \
  --tower "$TOWER" \
  --skip-preflight >"$SEND_LOG" 2>&1 || {
    echo "[!] sender failed:"
    cat "$SEND_LOG"
    exit 1
  }

wait "$RECV_PID" || {
  echo "[!] receiver returned non-zero:"
  cat "$RECV_LOG"
  exit 1
}

# Compare the parsed byte arrays — JSON whitespace differs, contents must not.
node -e '
  const fs = require("fs");
  const a = JSON.parse(fs.readFileSync(process.argv[1]));
  const b = JSON.parse(fs.readFileSync(process.argv[2]));
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    console.error("FAIL: byte arrays differ");
    process.exit(1);
  }
  console.log("[ok ] keypair byte arrays match (" + a.length + " bytes)");
' "$KP" "$RECV"

# Verify the tower file was delivered.
DELIVERED_TOWER=""
for f in ./*.bin "$(dirname "$RECV")"/*.bin; do
  [ -f "$f" ] && DELIVERED_TOWER="$f" && break
done
if [ -n "$DELIVERED_TOWER" ] && cmp -s "$TOWER" "$DELIVERED_TOWER"; then
  echo "[ok ] tower file matches"
  rm -f "$DELIVERED_TOWER"
else
  echo "[!! ] tower file missing or different"
  exit 1
fi

# Verify file mode of the received keypair is 0600.
PERMS="$(stat -f '%Lp' "$RECV" 2>/dev/null || stat -c '%a' "$RECV")"
if [ "$PERMS" = "600" ]; then
  echo "[ok ] received keypair has mode 0600"
else
  echo "[!!] received keypair has mode $PERMS (expected 600)"
  exit 1
fi

echo
echo "PASS"
