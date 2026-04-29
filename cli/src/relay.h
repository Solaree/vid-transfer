#ifndef VIDX_RELAY_H
#define VIDX_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

// Default relay endpoint. Override with --relay or VIDX_RELAY env.
#define VIDX_DEFAULT_RELAY "https://vid-transfer-relay.fly.dev"

// Initialize libcurl globally. Idempotent. Call once at program start.
vidx_status_t relay_init(void);
void          relay_cleanup(void);

// Set the global TLS posture: if `pin_required` is true and the relay is
// HTTPS, the connection must verify the peer cert. (Default: true.)
void relay_set_tls_strict(int strict);

// Register a session with the relay. The relay enforces:
//   - prefix uniqueness (8-byte hash collision rejected for the TTL window)
//   - prefix == blake2b(pubkey)[:8]
// On success, the relay associates: prefix → { recipient_pubkey, expires_at, ciphertext: NULL }.
// `expires_at` is a unix timestamp the relay echoes back; we propagate it to the user.
vidx_status_t relay_create_session(const char *base_url,
                                   const uint8_t prefix[8],
                                   const uint8_t recipient_pubkey[32],
                                   int64_t *out_expires_at);

// Fetch the recipient pubkey for an existing session. The CALLER must
// re-hash the pubkey and confirm it matches `prefix` — otherwise the relay
// has lied. We do that check inside this function and fail closed.
vidx_status_t relay_get_session_pubkey(const char *base_url,
                                       const uint8_t prefix[8],
                                       uint8_t recipient_pubkey_out[32],
                                       int64_t *out_expires_at);

// Upload ciphertext for a session (one-shot; relay rejects re-uploads).
vidx_status_t relay_put_ciphertext(const char *base_url,
                                   const uint8_t prefix[8],
                                   const uint8_t *ct, size_t ct_len);

// Long-poll for ciphertext. Returns VIDX_OK + buffer when received, or
// VIDX_ERR_TIMEOUT after timeout_ms with no data. On success the caller
// receives a malloc'd buffer; caller must `free` after wiping.
vidx_status_t relay_wait_ciphertext(const char *base_url,
                                    const uint8_t prefix[8],
                                    int timeout_ms,
                                    uint8_t **out_ct, size_t *out_len);

// Health check (GET /healthz). Useful for `vid-transfer doctor`.
vidx_status_t relay_health(const char *base_url);

#endif
