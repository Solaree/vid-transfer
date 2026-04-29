#include "crypto.h"
#include "secure_mem.h"

#include <sodium.h>
#include <string.h>

vidx_status_t vidx_keygen_x25519(uint8_t pk[VIDX_X25519_PK_BYTES], uint8_t *sk)
{
    if (crypto_box_keypair(pk, sk) != 0) {
        log_error("crypto_box_keypair failed");
        return VIDX_ERR_CRYPTO;
    }
    return VIDX_OK;
}

vidx_status_t vidx_seal(const uint8_t *pt, size_t pt_len,
                        const uint8_t recipient_pk[VIDX_X25519_PK_BYTES],
                        uint8_t *out, size_t *out_len)
{
    size_t ct_len = pt_len + crypto_box_SEALBYTES;
    if (crypto_box_seal(out, pt, pt_len, recipient_pk) != 0) {
        log_error("crypto_box_seal failed");
        return VIDX_ERR_CRYPTO;
    }
    *out_len = ct_len;
    return VIDX_OK;
}

vidx_status_t vidx_seal_open(const uint8_t *ct, size_t ct_len,
                             const uint8_t recipient_pk[VIDX_X25519_PK_BYTES],
                             const uint8_t *recipient_sk,
                             uint8_t *out, size_t *out_len)
{
    if (ct_len < crypto_box_SEALBYTES) {
        log_error("ciphertext shorter than sealed-box overhead");
        return VIDX_ERR_CRYPTO;
    }
    size_t pt_len = ct_len - crypto_box_SEALBYTES;
    if (crypto_box_seal_open(out, ct, ct_len, recipient_pk, recipient_sk) != 0) {
        log_error("crypto_box_seal_open failed (auth/decrypt)");
        return VIDX_ERR_CRYPTO;
    }
    *out_len = pt_len;
    return VIDX_OK;
}

vidx_status_t vidx_pair_hash(const uint8_t *input, size_t input_len,
                             uint8_t out[VIDX_PAIR_PREFIX_LEN])
{
    // BLAKE2b's output length is part of its parameter block, so a request
    // for an 8-byte output is NOT bit-equal to a 64-byte output truncated.
    // We compute the full 64-byte (blake2b-512) digest and truncate, so the
    // relay (Node OpenSSL) can verify with `createHash("blake2b512")`.
    uint8_t full[crypto_generichash_BYTES_MAX]; // 64 bytes
    if (crypto_generichash(full, sizeof(full),
                           input, input_len, NULL, 0) != 0) {
        return VIDX_ERR_CRYPTO;
    }
    memcpy(out, full, VIDX_PAIR_PREFIX_LEN);
    sodium_memzero(full, sizeof(full));
    return VIDX_OK;
}

void vidx_random(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
}

vidx_status_t vidx_ed25519_check_sk(const uint8_t sk[64], uint8_t pk_out[32])
{
    uint8_t derived[32];
    if (crypto_sign_ed25519_sk_to_pk(derived, sk) != 0) {
        return VIDX_ERR_CRYPTO;
    }
    // libsodium stores the ed25519 secret key as seed||pk. Check the embedded
    // pk matches the seed-derived pk to catch corrupted keypair files early.
    if (sodium_memcmp(derived, sk + 32, 32) != 0) {
        log_error("validator keypair self-check failed: embedded pubkey "
                  "does not match the seed-derived pubkey");
        sodium_memzero(derived, sizeof(derived));
        return VIDX_ERR_VERIFY;
    }
    if (pk_out) memcpy(pk_out, derived, 32);
    sodium_memzero(derived, sizeof(derived));
    return VIDX_OK;
}
