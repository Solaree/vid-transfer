#define _POSIX_C_SOURCE 200809L

#include "commands.h"

#include "../bundle.h"
#include "../crypto.h"
#include "../keypair.h"
#include "../pairing.h"
#include "../relay.h"
#include "../secure_mem.h"
#include "../tower.h"
#include "../util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void print_banner(const char *code, int64_t expires_at)
{
    bool color = log_color_enabled();
    const char *C_BOX  = color ? "\x1b[36m"      : "";   // cyan
    const char *C_CODE = color ? "\x1b[1;32m"    : "";   // bold green
    const char *C_DIM  = color ? "\x1b[2m"       : "";
    const char *C_OFF  = color ? "\x1b[0m"       : "";

    fprintf(stderr,
        "\n"
        "%s┌─────────────────────────────────────────────────────────────┐%s\n"
        "%s│%s  Share this 6-word code with the sender:                   %s│%s\n"
        "%s│%s                                                             %s│%s\n",
        C_BOX, C_OFF,
        C_BOX, C_OFF, C_BOX, C_OFF,
        C_BOX, C_OFF, C_BOX, C_OFF);

    // Centre the code in a 61-char interior. We pad with spaces.
    int code_len = (int)strlen(code);
    int pad_left = (61 - code_len) / 2;
    if (pad_left < 1) pad_left = 1;
    int pad_right = 61 - pad_left - code_len;
    if (pad_right < 1) pad_right = 1;

    fprintf(stderr, "%s│%s%*s%s%s%s%*s%s│%s\n",
            C_BOX, C_OFF,
            pad_left, "",
            C_CODE, code, C_OFF,
            pad_right, "",
            C_BOX, C_OFF);

    fprintf(stderr,
        "%s│%s                                                             %s│%s\n"
        "%s└─────────────────────────────────────────────────────────────┘%s\n",
        C_BOX, C_OFF, C_BOX, C_OFF,
        C_BOX, C_OFF);

    if (expires_at > 0) {
        time_t now = time(NULL);
        long secs = (long)(expires_at - (int64_t)now);
        if (secs < 0) secs = 0;
        long mins = secs / 60;
        long ss   = secs % 60;
        fprintf(stderr, "  %sexpires in %ldm %lds%s — receiver and sender must compare words.\n",
                C_DIM, mins, ss, C_OFF);
    }
    fprintf(stderr, "  %sif the words DO NOT match, abort: the relay is being tampered with.%s\n\n",
            C_DIM, C_OFF);
}

int cmd_receive(const cmd_opts_t *o)
{
    const char *out_path = o->out_path ? o->out_path : "received-validator-keypair.json";

    // Refuse to overwrite by default.
    struct stat st;
    if (stat(out_path, &st) == 0) {
        if (!o->force_overwrite) {
            log_error("output file already exists: %s. Pass --force to overwrite.", out_path);
            return VIDX_ERR_USAGE;
        }
        log_warn("will overwrite existing %s on success", out_path);
    }

    log_step("generating ephemeral X25519 keypair");

    // Allocate sk in mlocked memory.
    uint8_t pk[32];
    uint8_t *sk = (uint8_t *)secure_alloc(32);
    if (!sk) {
        log_error("secure_alloc failed; mlock may not be permitted on this host. "
                  "Try setting RLIMIT_MEMLOCK higher or running with cap_ipc_lock.");
        return VIDX_ERR_INTERNAL;
    }
    secure_register(sk, 32);

    vidx_status_t s = vidx_keygen_x25519(pk, sk);
    if (s != VIDX_OK) goto out;

    uint8_t prefix[8];
    s = vidx_pair_hash(pk, 32, prefix);
    if (s != VIDX_OK) goto out;

    char code[VIDX_PAIRING_CODE_MAX];
    s = pairing_encode(prefix, code, sizeof(code));
    if (s != VIDX_OK) goto out;

    log_step("registering session with relay %s", o->relay_url);
    relay_set_tls_strict(o->tls_strict);
    int64_t expires_at = 0;
    s = relay_create_session(o->relay_url, prefix, pk, &expires_at);
    if (s != VIDX_OK) goto out;

    print_banner(code, expires_at);

    log_step("waiting for sender (timeout %d seconds)", o->wait_seconds);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    s = relay_wait_ciphertext(o->relay_url, prefix,
                              o->wait_seconds * 1000,
                              &ct, &ct_len);
    if (s != VIDX_OK) {
        log_error("did not receive ciphertext: %s", vidx_status_str(s));
        goto out;
    }
    log_ok("received %zu bytes of ciphertext", ct_len);

    if (ct_len > VIDX_BUNDLE_MAX_TOTAL + 256) {
        log_error("ciphertext is implausibly large; refusing.");
        s = VIDX_ERR_VERIFY;
        goto out_ct;
    }

    log_step("decrypting bundle");

    uint8_t *pt = (uint8_t *)secure_alloc(ct_len + 1);
    if (!pt) { s = VIDX_ERR_INTERNAL; goto out_ct; }
    secure_register(pt, ct_len + 1);

    size_t pt_len = 0;
    s = vidx_seal_open(ct, ct_len, pk, sk, pt, &pt_len);
    if (s != VIDX_OK) {
        log_error("decryption failed (auth/integrity failure)");
        secure_free(pt);
        goto out_ct;
    }
    log_ok("decrypted %zu bytes", pt_len);

    // Wipe ciphertext now that we have the plaintext.
    secure_wipe(ct, ct_len);
    free(ct);
    ct = NULL;

    vidx_bundle_t b;
    s = bundle_decode(pt, pt_len, &b);
    if (s != VIDX_OK) {
        log_error("bundle decode failed");
        secure_free(pt);
        goto out;
    }

    // Now that the bundle owns the keypair, we can wipe the plaintext buffer.
    secure_free(pt);
    pt = NULL;

    // Self-check: the keypair's embedded pubkey must equal the bundle's
    // expected_pk, and a fresh derivation from the seed must match too.
    uint8_t derived_pk[32];
    vidx_status_t cs = vidx_ed25519_check_sk(b.keypair, derived_pk);
    if (cs != VIDX_OK) {
        log_error("decrypted keypair failed self-check");
        bundle_free(&b);
        s = cs;
        goto out;
    }
    if (memcmp(derived_pk, b.expected_pk, 32) != 0) {
        log_error("decrypted keypair does not match expected_pk in bundle (corruption?)");
        bundle_free(&b);
        s = VIDX_ERR_VERIFY;
        goto out;
    }

    char actual_b58[64];
    s = pubkey_to_base58(derived_pk, actual_b58, sizeof(actual_b58));
    if (s != VIDX_OK) { bundle_free(&b); goto out; }

    log_ok("validator identity: %s", actual_b58);
    if (b.source_hint[0]) log_info("source: %s", b.source_hint);
    if (b.timestamp > 0) {
        time_t tt = (time_t)b.timestamp;
        struct tm tm;
        char ts[40];
        gmtime_r(&tt, &tm);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
        log_info("bundled at: %s (unix=%" PRId64 ")", ts, b.timestamp);
    }

    if (o->expected_pubkey) {
        if (strcmp(o->expected_pubkey, actual_b58) != 0) {
            log_error("PIN MISMATCH: --expected-pubkey was %s, got %s. ABORTING.",
                      o->expected_pubkey, actual_b58);
            bundle_free(&b);
            s = VIDX_ERR_VERIFY;
            goto out;
        }
        log_ok("identity matches the pinned --expected-pubkey");
    }

    log_step("writing keypair to %s (mode 0600)", out_path);
    s = keypair_write(out_path, b.keypair);
    if (s != VIDX_OK) { bundle_free(&b); goto out; }

    if (b.tower && b.tower_len > 0) {
        char fname[VIDX_BUNDLE_MAX_FNAME + 1] = {0};
        if (b.tower_filename[0]) {
            snprintf(fname, sizeof(fname), "%s", b.tower_filename);
        } else {
            tower_canonical_name(actual_b58, fname, sizeof(fname));
        }
        char tower_out[4096];
        const char *dir = o->ledger_dir;
        if (dir) {
            int wn = snprintf(tower_out, sizeof(tower_out), "%s/%s", dir, fname);
            if (wn < 0 || (size_t)wn >= sizeof(tower_out)) {
                log_error("tower output path too long");
                bundle_free(&b);
                s = VIDX_ERR_INTERNAL;
                goto out;
            }
        } else {
            // Drop next to keypair.
            int wn = snprintf(tower_out, sizeof(tower_out), "./%s", fname);
            if (wn < 0 || (size_t)wn >= sizeof(tower_out)) {
                bundle_free(&b);
                s = VIDX_ERR_INTERNAL;
                goto out;
            }
        }
        s = tower_write(tower_out, b.tower, b.tower_len);
        if (s != VIDX_OK) { bundle_free(&b); goto out; }
        log_ok("wrote tower file: %s (%zu bytes)", tower_out, b.tower_len);
    } else {
        log_warn("no tower file in bundle. The new server will start with a fresh tower; "
                 "you MUST wait for the previous server to fully release the identity "
                 "before booting on this one to avoid double-signing.");
    }

    bundle_free(&b);
    log_ok("transfer complete");

    secure_free(sk);
    if (ct) free(ct);
    return 0;

out_ct:
    if (ct) {
        secure_wipe(ct, ct_len);
        free(ct);
    }
out:
    if (sk) secure_free(sk);
    return s;
}
