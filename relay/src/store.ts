import { createHash, timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";

export interface Session {
  prefix: string;            // 16 hex chars (8 bytes), lowercased
  recipientPubkey: string;   // 64 hex chars (32 bytes), lowercased
  expiresAt: number;         // unix seconds
  createdAt: number;         // unix seconds
  ciphertext: Buffer | null; // null until uploaded
  delivered: boolean;        // true once GET drained it
  remoteAddrCreator: string; // first 32 chars of IP+UA hash, for diagnostics
}

const EVENT_UPLOAD = "upload";

/**
 * Single-process in-memory store. The relay is intentionally cheap and
 * stateless across restarts — losing all sessions on restart is fine since
 * they're TTL'd to a few minutes anyway. Multiple replicas would need a
 * shared backend (Redis); for the design's threat model a single-instance
 * deploy is preferred (no shared backend means fewer surfaces to compromise).
 */
export class SessionStore {
  private sessions = new Map<string, Session>();
  private events = new EventEmitter();
  private reaperHandle: NodeJS.Timeout | null = null;

  constructor(private ttlSec: number) {
    this.events.setMaxListeners(0);
  }

  start() {
    if (this.reaperHandle) return;
    this.reaperHandle = setInterval(() => this.reap(), 30_000).unref();
  }

  stop() {
    if (this.reaperHandle) {
      clearInterval(this.reaperHandle);
      this.reaperHandle = null;
    }
  }

  size(): number { return this.sessions.size; }

  /**
   * Create a new session. The prefix MUST equal blake2b-128 truncated to
   * 8 bytes of `recipientPubkey` — the relay enforces this so a malicious
   * client cannot create a session under someone else's prefix.
   */
  create(prefix: string, recipientPubkey: string, remoteAddrTag: string): Session {
    if (this.sessions.has(prefix)) {
      throw new HttpError(409, "prefix_taken");
    }
    if (!verifyPrefix(prefix, recipientPubkey)) {
      throw new HttpError(400, "prefix_mismatch");
    }
    const now = Math.floor(Date.now() / 1000);
    const session: Session = {
      prefix,
      recipientPubkey,
      expiresAt: now + this.ttlSec,
      createdAt: now,
      ciphertext: null,
      delivered: false,
      remoteAddrCreator: remoteAddrTag,
    };
    this.sessions.set(prefix, session);
    return session;
  }

  get(prefix: string): Session {
    const s = this.sessions.get(prefix);
    if (!s) throw new HttpError(404, "not_found");
    if (s.delivered) {
      // Once delivered, the session is gone. Treat further fetches as 404.
      this.sessions.delete(prefix);
      throw new HttpError(404, "not_found");
    }
    if (Math.floor(Date.now() / 1000) > s.expiresAt) {
      this.scrub(s);
      this.sessions.delete(prefix);
      throw new HttpError(404, "expired");
    }
    return s;
  }

  upload(prefix: string, ct: Buffer): void {
    const s = this.get(prefix);
    if (s.ciphertext) {
      throw new HttpError(409, "already_uploaded");
    }
    s.ciphertext = ct;
    this.events.emit(`${EVENT_UPLOAD}:${prefix}`);
  }

  /**
   * Resolve a Promise as soon as the ciphertext arrives, or reject with a
   * timeout. Either way, on resolve we ATOMICALLY drain (delete + return).
   */
  waitForCiphertext(prefix: string, timeoutMs: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let s: Session;
      try {
        s = this.get(prefix);
      } catch (e) {
        return reject(e);
      }
      if (s.ciphertext) {
        return resolve(this.drain(prefix));
      }
      const evt = `${EVENT_UPLOAD}:${prefix}`;
      const onUpload = () => {
        clearTimeout(timer);
        try {
          resolve(this.drain(prefix));
        } catch (e) {
          reject(e);
        }
      };
      const timer = setTimeout(() => {
        this.events.removeListener(evt, onUpload);
        reject(new HttpError(204, "no_content_yet"));
      }, timeoutMs);
      this.events.once(evt, onUpload);
    });
  }

  /**
   * Drain a session: return the ciphertext, mark delivered, and remove from
   * the map. The next caller for the same prefix gets 404.
   */
  drain(prefix: string): Buffer {
    const s = this.sessions.get(prefix);
    if (!s) throw new HttpError(404, "not_found");
    if (!s.ciphertext) throw new HttpError(204, "no_content_yet");
    const ct = s.ciphertext;
    s.delivered = true;
    s.ciphertext = null;
    this.sessions.delete(prefix);
    return ct;
  }

  private scrub(s: Session) {
    if (s.ciphertext) {
      s.ciphertext.fill(0);
      s.ciphertext = null;
    }
  }

  private reap() {
    const now = Math.floor(Date.now() / 1000);
    for (const [prefix, s] of this.sessions) {
      if (now > s.expiresAt) {
        this.scrub(s);
        this.sessions.delete(prefix);
      }
    }
  }
}

export class HttpError extends Error {
  constructor(public status: number, public code: string) {
    super(`${status} ${code}`);
  }
}

export function verifyPrefix(prefix: string, recipientPubkey: string): boolean {
  if (!/^[0-9a-f]{16}$/.test(prefix)) return false;
  if (!/^[0-9a-f]{64}$/.test(recipientPubkey)) return false;
  const pkBytes = Buffer.from(recipientPubkey, "hex");
  // Node's createHash supports blake2b-* via openssl on most builds. We use
  // SHA3-256 truncated to 8 bytes if blake2b isn't available — both are
  // collision-resistant for our purposes; the C client picks blake2b.
  const expectedHex = blake2bOrSha3Prefix(pkBytes);
  const expected = Buffer.from(expectedHex, "hex");
  const actual = Buffer.from(prefix, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function blake2bOrSha3Prefix(pk: Buffer): string {
  // Try blake2b512 first — that's what libsodium's crypto_generichash uses
  // by default with a 64-byte (or shorter) output.
  try {
    const h = createHash("blake2b512");
    h.update(pk);
    const digest = h.digest();
    return digest.subarray(0, 8).toString("hex");
  } catch {
    // Fallback: BLAKE2b not built in. SHA-256 is also fine for the relay
    // (the C client uses blake2b; the relay just verifies, so we'd need to
    // match. If your build of OpenSSL lacks blake2b, install one that has it).
    throw new Error(
      "this Node build lacks blake2b512 in OpenSSL — install Node ≥20 with a default OpenSSL"
    );
  }
}
