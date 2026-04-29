import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import Fastify from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";

import { config } from "./config.js";
import { SessionStore } from "./store.js";
import { registerRoutes } from "./routes.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      // Serializers strip headers that could leak sensitive data into logs.
      serializers: {
        req(req) {
          return {
            method: req.method,
            url: req.url,
            ip: req.ip,
          };
        },
      },
    },
    bodyLimit: config.maxCiphertextBytes,
    trustProxy: config.trustProxy,
    disableRequestLogging: false,
  });

  // Body parser for raw octet-stream — used by ciphertext PUT.
  app.addContentTypeParser(
    "application/octet-stream",
    { parseAs: "buffer", bodyLimit: config.maxCiphertextBytes },
    (_req, body, done) => done(null, body)
  );

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
    hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
  });

  await app.register(cors, {
    origin: false, // No browser cross-origin access. CLI talks directly.
  });

  await app.register(rateLimit, {
    max: config.rateLimitMax,
    timeWindow: `${config.rateLimitWindowSec} seconds`,
    cache: 10_000,
    allowList: [],
    skipOnError: false,
  });

  const store = new SessionStore(config.sessionTtlSec);
  store.start();

  registerRoutes(app, store);

  if (config.serveLandingPage) {
    const publicDir = join(__dirname, "..", "public");
    await app.register(fastifyStatic, {
      root: publicDir,
      prefix: "/",
      decorateReply: false,
      // The landing page is informational — no authenticated content.
      cacheControl: true,
      maxAge: 60_000,
    });
  }

  // Graceful shutdown.
  const close = async (signal: string) => {
    app.log.info({ signal }, "shutting_down");
    store.stop();
    await app.close();
    process.exit(0);
  };
  process.on("SIGINT",  () => close("SIGINT"));
  process.on("SIGTERM", () => close("SIGTERM"));

  await app.listen({ port: config.port, host: config.host });
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error("fatal", e);
  process.exit(1);
});
