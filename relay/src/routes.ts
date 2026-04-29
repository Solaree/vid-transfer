import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";

import { config } from "./config.js";
import { HttpError, type SessionStore } from "./store.js";

interface CreateBody {
  prefix?: unknown;
  recipientPubkey?: unknown;
  version?: unknown;
}

function fingerprint(req: FastifyRequest): string {
  // 16 hex chars from a SHA-256 of the IP + UA. Used only to decorate logs.
  const ua = req.headers["user-agent"] ?? "";
  const ip = req.ip ?? "";
  return createHash("sha256").update(`${ip}|${ua}`).digest("hex").slice(0, 16);
}

export function registerRoutes(app: FastifyInstance, store: SessionStore) {
  app.get("/healthz", async () => ({ ok: true, sessions: store.size() }));

  app.get("/v1/info", async () => ({
    name: "vid-transfer-relay",
    version: "0.1.0",
    sessionTtlSec: config.sessionTtlSec,
    maxCiphertextBytes: config.maxCiphertextBytes,
    longPollTimeoutMs: config.longPollTimeoutMs,
  }));

  app.post<{ Body: CreateBody }>("/v1/sessions", async (req, reply) => {
    const { prefix, recipientPubkey, version } = req.body ?? {};
    if (typeof prefix !== "string" || typeof recipientPubkey !== "string") {
      return reply.code(400).send({ error: "prefix and recipientPubkey required" });
    }
    if (version !== 1) {
      return reply.code(400).send({ error: "unsupported version" });
    }
    const pfx = prefix.toLowerCase();
    const pk = recipientPubkey.toLowerCase();
    try {
      const s = store.create(pfx, pk, fingerprint(req));
      req.log.info(
        { prefix: pfx, expiresAt: s.expiresAt, fp: s.remoteAddrCreator },
        "session_created"
      );
      return reply.code(201).send({
        prefix: s.prefix,
        expiresAt: s.expiresAt,
        sessionTtlSec: config.sessionTtlSec,
      });
    } catch (e) {
      if (e instanceof HttpError) {
        return reply.code(e.status).send({ error: e.code });
      }
      req.log.error({ err: e }, "session_create_failed");
      return reply.code(500).send({ error: "internal" });
    }
  });

  app.get<{ Params: { prefix: string } }>("/v1/sessions/:prefix", async (req, reply) => {
    const pfx = req.params.prefix.toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(pfx)) {
      return reply.code(400).send({ error: "bad_prefix" });
    }
    try {
      const s = store.get(pfx);
      return reply.send({
        prefix: s.prefix,
        recipientPubkey: s.recipientPubkey,
        expiresAt: s.expiresAt,
        hasCiphertext: !!s.ciphertext,
      });
    } catch (e) {
      if (e instanceof HttpError) {
        return reply.code(e.status).send({ error: e.code });
      }
      throw e;
    }
  });

  app.put<{ Params: { prefix: string } }>("/v1/sessions/:prefix/ciphertext", {
    bodyLimit: config.maxCiphertextBytes,
    config: {
      // Disable Fastify's automatic JSON parsing for this route — body is
      // raw bytes. We register a parser below in index.ts.
    },
  }, async (req, reply) => {
    const pfx = req.params.prefix.toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(pfx)) {
      return reply.code(400).send({ error: "bad_prefix" });
    }
    const ct = req.body as Buffer | undefined;
    if (!ct || ct.length === 0) {
      return reply.code(400).send({ error: "empty_body" });
    }
    if (ct.length > config.maxCiphertextBytes) {
      return reply.code(413).send({ error: "too_large" });
    }
    try {
      store.upload(pfx, ct);
      req.log.info({ prefix: pfx, bytes: ct.length, fp: fingerprint(req) }, "ciphertext_uploaded");
      return reply.code(204).send();
    } catch (e) {
      if (e instanceof HttpError) {
        return reply.code(e.status).send({ error: e.code });
      }
      throw e;
    }
  });

  app.get<{
    Params: { prefix: string };
    Querystring: { wait?: string };
  }>("/v1/sessions/:prefix/ciphertext", async (req, reply) => {
    const pfx = req.params.prefix.toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(pfx)) {
      return reply.code(400).send({ error: "bad_prefix" });
    }

    const wantsLongPoll = req.query.wait === "1";
    try {
      if (wantsLongPoll) {
        try {
          const ct = await store.waitForCiphertext(pfx, config.longPollTimeoutMs);
          reply.header("Content-Type", "application/octet-stream");
          return reply.send(ct);
        } catch (e) {
          if (e instanceof HttpError && e.status === 204) {
            return reply.code(204).send();
          }
          throw e;
        }
      } else {
        const ct = store.drain(pfx);
        reply.header("Content-Type", "application/octet-stream");
        return reply.send(ct);
      }
    } catch (e) {
      if (e instanceof HttpError) {
        if (e.status === 204) return reply.code(204).send();
        return reply.code(e.status).send({ error: e.code });
      }
      throw e;
    }
  });
}
