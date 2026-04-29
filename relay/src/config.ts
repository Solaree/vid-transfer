function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${name} must be a positive number, got: ${raw}`);
  }
  return n;
}

function envStr(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (!v) return fallback;
  return v === "1" || v.toLowerCase() === "true" || v.toLowerCase() === "yes";
}

export const config = {
  port: envInt("PORT", 8080),
  host: envStr("HOST", "0.0.0.0"),

  // How long an unclaimed pairing slot lives. Five minutes is plenty for an
  // operator to read words off one screen and type them on another.
  sessionTtlSec: envInt("VIDX_SESSION_TTL_SEC", 5 * 60),

  // Hard ceiling on ciphertext size. The plaintext bundle has a 256 KiB cap;
  // we add room for the sealed-box overhead and a generous safety margin.
  maxCiphertextBytes: envInt("VIDX_MAX_CIPHERTEXT", 320 * 1024),

  // How long we hold an HTTP request open in long-poll mode.
  longPollTimeoutMs: envInt("VIDX_LONGPOLL_MS", 25_000),

  // Rate limits.
  rateLimitMax: envInt("VIDX_RATE_LIMIT_MAX", 60),       // requests…
  rateLimitWindowSec: envInt("VIDX_RATE_LIMIT_WINDOW_SEC", 60),  // …per window per IP

  trustProxy: envBool("VIDX_TRUST_PROXY", true),

  serveLandingPage: envBool("VIDX_SERVE_LANDING", true),

  logLevel: envStr("LOG_LEVEL", "info"),
};

export type Config = typeof config;
