# vid-transfer relay

A short-lived rendezvous point for `vid-transfer`. Stores ciphertext only,
TTL'd, single-use. Runs as a single Node process; in-memory state only.

## Build & run

```bash
npm install
npm run build
node dist/index.js     # listens on :8080
```

For development, `npm run dev` uses `tsx watch`.

## API

Everything under `/v1`. Bodies that are not octet-streams are JSON.

### `POST /v1/sessions`

Register a recipient public key. Request body:

```json
{
  "version": 1,
  "prefix": "<16 hex chars (8 bytes)>",
  "recipientPubkey": "<64 hex chars (32 bytes)>"
}
```

`prefix` MUST equal `BLAKE2b-512(recipientPubkey)[0..8]` (the relay
verifies; mismatches return `400`). On success, returns `201` with:

```json
{ "prefix": "...", "expiresAt": 1745875200, "sessionTtlSec": 300 }
```

### `GET /v1/sessions/<prefix>`

Look up a session. Returns:

```json
{
  "prefix": "...",
  "recipientPubkey": "...",
  "expiresAt": 1745875200,
  "hasCiphertext": false
}
```

The CLI re-derives `BLAKE2b-512(recipientPubkey)[0..8]` and aborts if it
does not match the typed pairing code. **The relay cannot trick the CLI
into accepting a substituted public key** — that is the whole point of
this round trip.

### `PUT /v1/sessions/<prefix>/ciphertext`

Upload the sealed-box ciphertext. `Content-Type: application/octet-stream`,
body up to `VIDX_MAX_CIPHERTEXT` (default 320 KiB). Returns `204` on
success, `409` if already uploaded once, `413` if too large.

### `GET /v1/sessions/<prefix>/ciphertext[?wait=1]`

Drain the ciphertext. Without `wait=1`, returns `200` with bytes if
present or `204` if not yet uploaded. With `wait=1`, holds the request
open up to `VIDX_LONGPOLL_MS` and returns `200` as soon as the upload
arrives. **Either way, after a successful drain the session is deleted
from memory; the next call returns `404`.**

### `GET /healthz`

Returns `{"ok":true,"sessions":<count>}`.

### `GET /v1/info`

Returns the relay's runtime config (TTL, ciphertext cap, long-poll
window). Used by `vid-transfer doctor`.

## Configuration

See [../docs/DEPLOY.md](../docs/DEPLOY.md). All knobs are environment
variables. The defaults are tuned for a single-tenant operator.

## Security posture

- HTTPS termination is the platform's job (Fly.io / Railway / Caddy).
- Helmet sets a strict CSP, HSTS, and turns off referrer.
- CORS is closed (the relay is for CLIs, not browsers).
- Rate limiting is per-IP, default 60/min. PaaS platforms set `X-Forwarded-For`;
  the relay trusts it because we run behind those proxies.
- Body size is hard-capped at the configured `VIDX_MAX_CIPHERTEXT`.
- The body parser for ciphertext is strict — only `application/octet-stream`.
- `helmet`'s frame-ancestors directive is `'none'`, so the landing page
  cannot be iframed for clickjacking.

## What the relay never sees

- The validator's private key (the bundle is sealed-box encrypted).
- The pairing-code words (only the 8-byte hash prefix).
- Any indication of which validator pubkey is being moved (the bundle
  carries that, encrypted; the wire never carries it in clear).

## What the relay logs

Three structured Pino events, no payload contents:

- `session_created` — `prefix`, `expiresAt`, fingerprint hash.
- `ciphertext_uploaded` — `prefix`, `bytes`, fingerprint hash.
- platform-level access logs (method, URL, status, duration).

The fingerprint is `sha256(ip||user_agent)[0..16]` — a stable identifier
within one request flight, useless for cross-correlation later.
