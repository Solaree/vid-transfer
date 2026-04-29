# Deploying a vid-transfer relay

The relay is intentionally tiny: one Node.js process, no database, no
disk persistence. It's safe to run on any platform that can speak HTTPS
and serve a 256 MB container. This document covers four targets:

- [Fly.io](#flyio) (recommended for the live submission demo)
- [Railway](#railway) (one-click PaaS alternative)
- [Plain Docker](#plain-docker) (bring-your-own-VPS)
- [Local development](#local-development)

Whichever platform you choose, **the operator's host must be able to
verify the relay's TLS certificate.** That is the entire trust assumption
between operator and relay.

## Configuration

All configuration is environment variables; there is no config file.

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Listen port. |
| `HOST` | `0.0.0.0` | Listen address. |
| `VIDX_SESSION_TTL_SEC` | `300` | How long an unclaimed pairing slot lives. |
| `VIDX_MAX_CIPHERTEXT` | `327680` | Hard ceiling on uploaded ciphertext bytes. |
| `VIDX_LONGPOLL_MS` | `25000` | How long a `?wait=1` GET stays open before returning 204. |
| `VIDX_RATE_LIMIT_MAX` | `60` | Requests per IP per window. |
| `VIDX_RATE_LIMIT_WINDOW_SEC` | `60` | Rate-limit window. |
| `VIDX_TRUST_PROXY` | `true` | Trust `X-Forwarded-For` (PaaS load balancers). |
| `VIDX_SERVE_LANDING` | `true` | Serve the static landing page at `/`. |
| `LOG_LEVEL` | `info` | `pino` log level (`trace`, `debug`, `info`, `warn`, `error`). |

## Fly.io

```bash
cd relay
fly auth login
fly launch --no-deploy --copy-config --name <your-app-name>
# fly will offer to set up a Postgres / Redis — say no.

fly deploy
```

The bundled `fly.toml` defines:

- a `shared-cpu-1x` machine with 256 MB RAM (well below the cost of one
  validator-second),
- HTTP healthchecks on `/healthz`,
- TLS termination on 443,
- automatic stop/start when idle.

After `fly deploy`, point the CLI at the new hostname:

```bash
export VIDX_RELAY=https://<your-app-name>.fly.dev
vid-transfer doctor
```

## Railway

```bash
railway login
railway init      # in relay/, pick "deploy from Dockerfile"
railway up
```

Railway will read `railway.json` and use the `Dockerfile`. The
`/healthz` probe is configured automatically. Set environment variables
through the Railway dashboard or the CLI:

```bash
railway variables --set VIDX_SESSION_TTL_SEC=300
railway variables --set VIDX_MAX_CIPHERTEXT=327680
```

## Plain Docker

```bash
cd relay
docker build -t vid-transfer-relay .
docker run -d --name vid-transfer-relay \
  -p 8080:8080 \
  -e VIDX_SESSION_TTL_SEC=300 \
  -e VIDX_MAX_CIPHERTEXT=327680 \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges \
  --user 1000 \
  vid-transfer-relay
```

Put a real reverse proxy in front (Caddy, nginx, traefik) for TLS — the
relay itself does not terminate TLS. A 30-line `Caddyfile` is enough:

```
relay.example.com {
  encode gzip
  reverse_proxy 127.0.0.1:8080 {
    header_up X-Forwarded-Proto {scheme}
    header_up X-Forwarded-For   {remote_host}
  }
}
```

## Local development

```bash
cd relay
npm install
npm run dev          # tsx watch
# in another shell:
curl http://127.0.0.1:8080/healthz
```

Talk to it from the CLI with `--relay http://127.0.0.1:8080
--insecure-tls` (the latter only because there's no cert on plain HTTP;
without it the CLI is fine, since CURLOPT_SSL_VERIFYPEER only applies to
HTTPS).

## Hardening checklist for production

- [ ] Run on a TLS endpoint with a real certificate (Let's Encrypt or
      provider-issued).
- [ ] Restrict outbound network access from the relay; it does not need
      egress for normal operation.
- [ ] Set `VIDX_RATE_LIMIT_MAX` low (e.g., 30/min) if you only expect
      yourself to use it.
- [ ] If you operate the relay for multiple operators, monitor the
      `session_created` and `ciphertext_uploaded` Pino events for
      anomalies.
- [ ] Periodically restart the relay (cron + `kubectl rollout restart`,
      `fly machines restart`, etc.) to bound the lifetime of any
      in-memory state — sessions are TTL-bounded but a 60-minute restart
      is a cheap defense in depth.
- [ ] **Do not** add Redis or any shared backing store. The relay's
      design assumes per-instance memory only; persisting ciphertext
      breaks the "no third-party copies" property.
