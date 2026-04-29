#ifndef VIDX_CRYPTO_H
#define VIDX_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

// X25519 (libsodium crypto_box / sealed-box) parameters.
#define VIDX_X25519_PK_BYTES 32
#define VIDX_X25519_SK_BYTES 32

// crypto_box_seal overhead: ephemeral pk (32) + MAC (16) = 48 bytes.
#define VIDX_SEAL_OVERHEAD   48

// blake2b 8-byte hash used as the pairing prefix.
#define VIDX_PAIR_PREFIX_LEN 8

// Generate an ephemeral X25519 keypair. `sk` must be a buffer from secure_alloc.
vidx_status_t vidx_keygen_x25519(uint8_t pk[VIDX_X25519_PK_BYTES], uint8_t *sk);

// Anonymous sealed box: encrypt `pt[pt_len]` to `recipient_pk`. Caller provides
// `out` of size `pt_len + VIDX_SEAL_OVERHEAD`.
vidx_status_t vidx_seal(const uint8_t *pt, size_t pt_len,
                        const uint8_t recipient_pk[VIDX_X25519_PK_BYTES],
                        uint8_t *out, size_t *out_len);

// Open a sealed box. `sk`/`pk` are the recipient's keypair.
vidx_status_t vidx_seal_open(const uint8_t *ct, size_t ct_len,
                             const uint8_t recipient_pk[VIDX_X25519_PK_BYTES],
                             const uint8_t *recipient_sk,
                             uint8_t *out, size_t *out_len);

// blake2b(input) → first VIDX_PAIR_PREFIX_LEN bytes used as the pairing tag.
vidx_status_t vidx_pair_hash(const uint8_t *input, size_t input_len,
                             uint8_t out[VIDX_PAIR_PREFIX_LEN]);

// Random bytes (libsodium CSPRNG).
void vidx_random(uint8_t *buf, size_t len);

// Validate that an ed25519 64-byte secret-key blob (libsodium format = seed||pk)
// has a self-consistent embedded public key. Optionally derive that pubkey.
vidx_status_t vidx_ed25519_check_sk(const uint8_t sk[64], uint8_t pk_out[32]);

#endif
