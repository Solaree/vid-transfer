#include "commands.h"

#include "../crypto.h"
#include "../keypair.h"
#include "../relay.h"
#include "../secure_mem.h"
#include "../solana_rpc.h"
#include "../util.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void check(const char *name, vidx_status_t s, const char *detail)
{
    if (s == VIDX_OK) {
        log_ok("%-22s %s", name, detail ? detail : "ok");
    } else {
        log_error("%-22s FAIL (%s) %s", name, vidx_status_str(s), detail ? detail : "");
    }
}

int cmd_doctor(const cmd_opts_t *o)
{
    int failed = 0;

    log_step("running diagnostics");

    // 1. libsodium init.
    if (sodium_init() < 0) {
        log_error("libsodium init failed — refusing to continue");
        return VIDX_ERR_CRYPTO;
    }
    check("libsodium", VIDX_OK, sodium_version_string());

    // 2. Sealed-box round trip on random data.
    {
        uint8_t pk[32];
        uint8_t *sk = (uint8_t *)secure_alloc(32);
        if (!sk) { log_error("secure_alloc failed (mlock?)"); return VIDX_ERR_INTERNAL; }
        secure_register(sk, 32);

        vidx_status_t s = vidx_keygen_x25519(pk, sk);
        if (s != VIDX_OK) { failed++; check("crypto/keygen", s, NULL); secure_free(sk); }
        else {
            uint8_t pt[64];
            randombytes_buf(pt, sizeof(pt));
            uint8_t ct[64 + 48];
            size_t ct_len = 0;
            s = vidx_seal(pt, sizeof(pt), pk, ct, &ct_len);
            if (s != VIDX_OK) { failed++; check("crypto/seal", s, NULL); secure_free(sk); }
            else {
                uint8_t out[64];
                size_t out_len = 0;
                s = vidx_seal_open(ct, ct_len, pk, sk, out, &out_len);
                if (s == VIDX_OK && out_len == 64 && memcmp(out, pt, 64) == 0) {
                    check("crypto/sealed-box", VIDX_OK, "encrypt+decrypt round-trip");
                } else {
                    failed++;
                    check("crypto/sealed-box", VIDX_ERR_CRYPTO, "round-trip mismatch");
                }
            }
            secure_free(sk);
        }
    }

    // 3. Relay reachability.
    {
        vidx_status_t s = relay_init();
        if (s != VIDX_OK) { failed++; check("relay/init", s, NULL); }
        else {
            relay_set_tls_strict(o->tls_strict);
            s = relay_health(o->relay_url);
            if (s != VIDX_OK) failed++;
            char detail[256];
            snprintf(detail, sizeof(detail), "%s", o->relay_url);
            check("relay/health", s, detail);
        }
    }

    // 4. Solana RPC reachability.
    {
        char ver[64] = "";
        vidx_status_t s = solana_get_version(o->rpc_url, ver, sizeof(ver));
        if (s != VIDX_OK) failed++;
        char detail[160];
        snprintf(detail, sizeof(detail), "%s (%s)", o->rpc_url, ver[0] ? ver : "n/a");
        check("rpc/getVersion", s, detail);
    }

    // 5. Keypair file (if path provided).
    if (o->keypair_path) {
        uint8_t *sk = (uint8_t *)secure_alloc(64);
        if (!sk) { log_error("secure_alloc failed"); return VIDX_ERR_INTERNAL; }
        secure_register(sk, 64);
        char b58[64];
        vidx_status_t s = keypair_read(o->keypair_path, sk, NULL, b58,
                                       o->allow_loose_perms);
        if (s != VIDX_OK) failed++;
        char detail[160];
        snprintf(detail, sizeof(detail), "%s -> %s", o->keypair_path, s == VIDX_OK ? b58 : "(unreadable)");
        check("keypair/parse", s, detail);
        secure_free(sk);
    }

    if (failed > 0) {
        log_error("%d check(s) failed.", failed);
        return VIDX_ERR_INTERNAL;
    }
    log_ok("all checks passed.");
    return 0;
}
