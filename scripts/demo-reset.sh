#!/usr/bin/env bash
#
# Reset state between demo takes. Safe to run as many times as you like.
#
#   bash scripts/demo-reset.sh
#
# Use it before every recording attempt — guarantees a clean run.

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "→ killing any vid-transfer processes still running…"
pkill -f vid-transfer 2>/dev/null || true

echo "→ removing leftover output files…"
rm -f /tmp/recv.json

echo "→ ensuring a test validator keypair exists at /tmp/vidx-test-validator.json…"
if [ ! -f /tmp/vidx-test-validator.json ]; then
  if command -v solana-keygen >/dev/null 2>&1; then
    solana-keygen new --silent --no-bip39-passphrase \
      --outfile /tmp/vidx-test-validator.json >/dev/null
  else
    node -e '
      const c = require("crypto"); const fs = require("fs");
      const { publicKey, privateKey } = c.generateKeyPairSync("ed25519");
      const sk = privateKey.export({ format: "der", type: "pkcs8" });
      const seed = sk.subarray(sk.length - 32);
      const pk = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
      fs.writeFileSync(process.argv[1],
        JSON.stringify(Array.from(Buffer.concat([seed, pk]))));
    ' /tmp/vidx-test-validator.json
  fi
  chmod 600 /tmp/vidx-test-validator.json
fi

echo "→ pinging the live relay…"
if curl -sf https://vid-transfer-relay.fly.dev/healthz >/dev/null; then
  echo "  ✓ relay is up"
else
  echo "  ✗ relay unreachable — fly machine start vid-transfer-relay"
  exit 1
fi

PUBKEY="$(node -e '
  const fs = require("fs");
  const arr = JSON.parse(fs.readFileSync("/tmp/vidx-test-validator.json"));
  const sk = Buffer.from(arr); const pk = sk.subarray(32);
  // base58 encode (small inline implementation)
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let z = 0; while (z < pk.length && pk[z] === 0) z++;
  const buf = new Uint8Array(pk.length * 2);
  let high = buf.length - 1;
  for (let i = z; i < pk.length; i++) {
    let carry = pk[i], j = buf.length - 1;
    while (true) {
      carry += buf[j] * 256; buf[j] = carry % 58; carry = (carry / 58) | 0;
      if (j === 0 || (j <= high && carry === 0)) { if (j < high) high = j; break; }
      j--;
    }
  }
  let out = "";
  for (let i = 0; i < z; i++) out += "1";
  for (let i = high; i < buf.length; i++) out += A[buf[i]];
  console.log(out);
' 2>/dev/null)"

echo
echo "  test identity: $PUBKEY"
echo
echo "  ready. paste these into the two terminals when you hit record:"
echo
echo "  --- NEW HOST ---"
echo "  cli/build/vid-transfer receive --out /tmp/recv.json --no-tower --wait 120 --force"
echo
echo "  --- OLD HOST ---"
echo "  echo y | cli/build/vid-transfer send <PASTE-CODE-HERE> \\"
echo "    --keypair /tmp/vidx-test-validator.json \\"
echo "    --skip-preflight --no-tower"
echo
