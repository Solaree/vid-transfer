#ifndef VIDX_KEYPAIR_H
#define VIDX_KEYPAIR_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define VIDX_ED25519_SK_LEN 64
#define VIDX_ED25519_PK_LEN 32
#define VIDX_PK_BASE58_MAX  64  // 32 bytes encodes to ~44 chars

// Read a solana-keygen style keypair file: a JSON array of 64 integers, each
// 0..255, representing a libsodium ed25519 secret key (seed||pk).
//
// `sk_out` MUST be a 64-byte buffer obtained from secure_alloc(). On success
// we self-check the embedded pubkey, optionally write it to `pk_out`, and
// also produce a base58 string in `pk_b58` (caller-allocated, ≥45 bytes).
//
// The function refuses files that aren't 0600 / 0400 unless `allow_loose_perms`
// is set. It also rejects symlinks.
vidx_status_t keypair_read(const char *path,
                           uint8_t *sk_out /* 64 */,
                           uint8_t *pk_out /* 32, optional */,
                           char *pk_b58 /* >=45, optional */,
                           bool allow_loose_perms);

// Write a 64-byte ed25519 secret key as a JSON array file with 0600 perms.
// The file is written atomically (tmp + rename).
vidx_status_t keypair_write(const char *path, const uint8_t *sk /* 64 */);

// Encode 32-byte pubkey to base58 NUL-terminated string in `out`.
// `out` must be ≥45 bytes.
vidx_status_t pubkey_to_base58(const uint8_t pk[VIDX_ED25519_PK_LEN], char *out, size_t out_size);

// Decode base58 pubkey string into 32 bytes. Returns VIDX_ERR_PARSE on bad input.
vidx_status_t pubkey_from_base58(const char *s, uint8_t pk_out[VIDX_ED25519_PK_LEN]);

#endif
