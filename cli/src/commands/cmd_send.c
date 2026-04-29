#define _POSIX_C_SOURCE 200809L

#include "commands.h"

#include "../bundle.h"
#include "../crypto.h"
#include "../keypair.h"
#include "../pairing.h"
#include "../relay.h"
#include "../secure_mem.h"
#include "../solana_rpc.h"
#include "../tower.h"
#include "../util.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SAFE_SLOTS_BEFORE_LEADER 200

static vidx_status_t preflight(const cmd_opts_t *o, const char *identity_b58)
{
    if (o->skip_preflight) {
        log_warn("--skip-preflight set: NOT checking the leader schedule. "
                 "If you are about to be leader, you may double-sign and "
                 "lose stake. Continuing because you asked.");
        return VIDX_OK;
    }

    log_step("pre-flight: querying leader schedule");
    solana_leader_summary_t ls;
    vidx_status_t s = solana_get_leader_summary(o->rpc_url, identity_b58, &ls);
    if (s != VIDX_OK) {
        log_warn("leader-schedule check failed (%s). Run `vid-transfer status` "
                 "or pass --rpc to point at a working RPC. Use --skip-preflight "
                 "ONLY if you've manually confirmed the validator is idle.",
                 vidx_status_str(s));
        return VIDX_ERR_RPC;
    }
    if (ls.has_next && ls.slots_until_next < SAFE_SLOTS_BEFORE_LEADER) {
        log_error("UNSAFE: this validator's next leader slot is %llu (in %llu slots, ~%llu s). "
                  "Wait until past that window before transferring identity.",
                  (unsigned long long)ls.next_leader_slot,
                  (unsigned long long)ls.slots_until_next,
                  (unsigned long long)(ls.slots_until_next * 4 / 10));
        return VIDX_ERR_VERIFY;
    }
    log_ok("leader schedule check passed (%s)",
           ls.has_next ? "next slot far enough away" : "no remaining leader slots in this epoch");
    return VIDX_OK;
}

int cmd_send(const cmd_opts_t *o)
{
    if (!o->code) {
        log_error("pairing code required");
        return VIDX_ERR_USAGE;
    }
    if (!o->keypair_path) {
        log_error("--keypair PATH required");
        return VIDX_ERR_USAGE;
    }

    // Decode the pairing code locally (catches typos before talking to the relay).
    uint8_t prefix[8];
    vidx_status_t s = pairing_decode(o->code, prefix);
    if (s != VIDX_OK) return s;
    log_ok("pairing code decoded");

    // Read keypair (mlocked).
    uint8_t *sk = (uint8_t *)secure_alloc(64);
    if (!sk) return VIDX_ERR_INTERNAL;
    secure_register(sk, 64);

    uint8_t identity_pk[32];
    char    identity_b58[64];
    s = keypair_read(o->keypair_path, sk, identity_pk, identity_b58,
                     o->allow_loose_perms);
    if (s != VIDX_OK) { secure_free(sk); return s; }
    log_ok("local validator identity: %s", identity_b58);

    // Pre-flight (safe-window check).
    s = preflight(o, identity_b58);
    if (s != VIDX_OK) { secure_free(sk); return s; }

    // Locate tower file.
    uint8_t *tower_data = NULL;
    size_t   tower_len  = 0;
    char     tower_fname[VIDX_BUNDLE_MAX_FNAME + 1] = {0};

    if (o->no_tower) {
        log_warn("--no-tower: tower file will NOT be transferred. The receiver will "
                 "start with no prior tower; this is risky. Only use this if you "
                 "fully understand the slashing implications.");
    } else if (o->tower_path) {
        s = tower_read(o->tower_path, &tower_data, &tower_len);
        if (s != VIDX_OK) {
            log_error("could not read tower file %s", o->tower_path);
            secure_free(sk);
            return s;
        }
        const char *base = strrchr(o->tower_path, '/');
        snprintf(tower_fname, sizeof(tower_fname), "%s", base ? base + 1 : o->tower_path);
        log_ok("tower file: %s (%zu bytes)", o->tower_path, tower_len);
    } else if (o->ledger_dir) {
        char path[4096];
        bool present = false;
        s = tower_locate(o->ledger_dir, identity_b58, path, sizeof(path), &present);
        if (s == VIDX_OK && present) {
            s = tower_read(path, &tower_data, &tower_len);
            if (s != VIDX_OK) {
                log_error("found tower at %s but could not read it", path);
                secure_free(sk);
                return s;
            }
            tower_canonical_name(identity_b58, tower_fname, sizeof(tower_fname));
            log_ok("tower file: %s (%zu bytes)", path, tower_len);
        } else {
            log_warn("no tower found in %s for identity %s — sending without tower",
                     o->ledger_dir, identity_b58);
        }
    } else {
        log_warn("no --ledger-dir or --tower; sending keypair only. "
                 "Without the tower, the receiving validator must wait an extended "
                 "period before voting to avoid slashing.");
    }

    log_step("fetching recipient pubkey from relay (and verifying pairing)");
    uint8_t recipient_pk[32];
    int64_t expires_at = 0;
    relay_set_tls_strict(o->tls_strict);
    s = relay_get_session_pubkey(o->relay_url, prefix, recipient_pk, &expires_at);
    if (s != VIDX_OK) {
        secure_free(sk);
        if (tower_data) { secure_wipe(tower_data, tower_len); free(tower_data); }
        return s;
    }
    log_ok("relay pubkey verified against pairing code");

    if (expires_at > 0) {
        time_t now = time(NULL);
        long secs = (long)(expires_at - (int64_t)now);
        if (secs < 60) {
            log_warn("session expires in %lds — proceeding immediately", secs);
        } else {
            log_info("session expires in %ld seconds", secs);
        }
    }

    // Build bundle.
    vidx_bundle_t b;
    bundle_init(&b);
    b.timestamp = (int64_t)time(NULL);
    memcpy(b.expected_pk, identity_pk, 32);
    memcpy(b.keypair, sk, 64);

    char host[256] = "unknown-host";
    if (gethostname(host, sizeof(host) - 1) == 0) host[sizeof(host) - 1] = '\0';
    snprintf(b.source_hint, sizeof(b.source_hint), "%s", host);

    if (tower_data && tower_len > 0) {
        b.tower = tower_data;
        b.tower_len = tower_len;
        snprintf(b.tower_filename, sizeof(b.tower_filename), "%s", tower_fname);
    }

    uint8_t *bundle_bytes = NULL;
    size_t   bundle_len = 0;
    s = bundle_encode(&b, &bundle_bytes, &bundle_len);
    if (s != VIDX_OK) { bundle_free(&b); secure_free(sk); return s; }
    log_ok("bundle prepared: %zu bytes plaintext", bundle_len);

    // Encrypt.
    log_step("sealing to recipient");
    size_t ct_len = bundle_len + VIDX_SEAL_OVERHEAD;
    uint8_t *ct = (uint8_t *)malloc(ct_len);
    if (!ct) {
        sodium_memzero(bundle_bytes, bundle_len);
        free(bundle_bytes);
        bundle_free(&b);
        secure_free(sk);
        return VIDX_ERR_INTERNAL;
    }
    s = vidx_seal(bundle_bytes, bundle_len, recipient_pk, ct, &ct_len);
    sodium_memzero(bundle_bytes, bundle_len);
    free(bundle_bytes);
    bundle_free(&b);
    secure_free(sk);
    if (s != VIDX_OK) {
        sodium_memzero(ct, ct_len);
        free(ct);
        return s;
    }
    log_ok("ciphertext: %zu bytes", ct_len);

    // Confirm with the user.
    if (!o->json_output) {
        char prompt_buf[256];
        snprintf(prompt_buf, sizeof(prompt_buf),
                 "Send %zu bytes of ciphertext now? Identity: %s",
                 ct_len, identity_b58);
        if (!prompt_yes_no(prompt_buf, true)) {
            log_warn("aborted by user");
            sodium_memzero(ct, ct_len);
            free(ct);
            return VIDX_ERR_USER_ABORT;
        }
    }

    log_step("uploading to relay");
    s = relay_put_ciphertext(o->relay_url, prefix, ct, ct_len);
    sodium_memzero(ct, ct_len);
    free(ct);
    if (s != VIDX_OK) return s;

    log_ok("upload complete. The receiver should report success momentarily.");
    log_info("Once you've confirmed the receiver booted with the identity, run "
             "`vid-transfer swap-out` here to switch this host to an unstaked identity.");
    return 0;
}
