#define _POSIX_C_SOURCE 200809L

#include "keypair.h"

#include "base58.h"
#include "crypto.h"
#include "secure_mem.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Parse a JSON array of integers 0..255 into bytes. Whitespace tolerant.
// Returns the count, or -1 on error.
static int parse_byte_array(const char *json, size_t json_len,
                            uint8_t *out, size_t out_max)
{
    size_t i = 0;
    // Skip leading whitespace.
    while (i < json_len && isspace((unsigned char)json[i])) i++;
    if (i >= json_len || json[i] != '[') return -1;
    i++;

    size_t n = 0;
    while (i < json_len) {
        while (i < json_len && (isspace((unsigned char)json[i]) || json[i] == ',')) i++;
        if (i >= json_len) break;
        if (json[i] == ']') return (int)n;

        // Parse integer.
        if (!isdigit((unsigned char)json[i]) && json[i] != '-' && json[i] != '+') {
            return -1;
        }
        char *end = NULL;
        long v = strtol(json + i, &end, 10);
        if (!end || end == json + i) return -1;
        if (v < 0 || v > 255) return -1;
        if (n >= out_max) return -1;
        out[n++] = (uint8_t)v;
        i = (size_t)(end - json);
    }
    return -1; // missing closing bracket
}

vidx_status_t keypair_read(const char *path,
                           uint8_t *sk_out,
                           uint8_t *pk_out,
                           char *pk_b58,
                           bool allow_loose_perms)
{
    if (!path || !sk_out) return VIDX_ERR_USAGE;

    struct stat st;
    if (lstat(path, &st) != 0) {
        log_error("lstat(%s): %s", path, strerror(errno));
        return VIDX_ERR_IO;
    }
    if (S_ISLNK(st.st_mode)) {
        log_error("%s is a symlink — refusing to read keypair through symlinks", path);
        return VIDX_ERR_PERM;
    }
    if (!S_ISREG(st.st_mode)) {
        log_error("%s is not a regular file", path);
        return VIDX_ERR_IO;
    }

    mode_t perms = st.st_mode & 0777;
    if ((perms & 0077) != 0) {
        // Group/other readable or writable.
        if (allow_loose_perms) {
            log_warn("%s permissions are %04o (group/other accessible). "
                     "Continuing because --allow-loose-perms was set; recommend chmod 600.",
                     path, perms);
        } else {
            log_error("%s permissions are %04o (group/other accessible). "
                      "Run `chmod 600 %s` first, or pass --allow-loose-perms to override.",
                      path, perms, path);
            return VIDX_ERR_PERM;
        }
    }

    // Read file contents into a *non-secure* heap buffer (it's just JSON text);
    // we'll wipe it after parse.
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    vidx_status_t s = read_file_all(path, &raw, &raw_len, 64 * 1024);
    if (s != VIDX_OK) return s;

    int n = parse_byte_array((const char *)raw, raw_len,
                             sk_out, VIDX_ED25519_SK_LEN);
    secure_wipe(raw, raw_len);
    free(raw);

    if (n < 0) {
        log_error("%s: failed to parse keypair (expected JSON array of 64 ints 0..255)", path);
        return VIDX_ERR_PARSE;
    }
    if (n != VIDX_ED25519_SK_LEN) {
        log_error("%s: keypair has %d bytes, expected %d", path, n, VIDX_ED25519_SK_LEN);
        return VIDX_ERR_PARSE;
    }

    uint8_t pk_local[VIDX_ED25519_PK_LEN];
    vidx_status_t cs = vidx_ed25519_check_sk(sk_out, pk_local);
    if (cs != VIDX_OK) {
        secure_wipe(sk_out, VIDX_ED25519_SK_LEN);
        secure_wipe(pk_local, sizeof(pk_local));
        return cs;
    }
    if (pk_out) memcpy(pk_out, pk_local, VIDX_ED25519_PK_LEN);
    if (pk_b58) {
        if (b58_encode(pk_local, VIDX_ED25519_PK_LEN, pk_b58, VIDX_PK_BASE58_MAX) < 0) {
            secure_wipe(pk_local, sizeof(pk_local));
            return VIDX_ERR_INTERNAL;
        }
    }
    secure_wipe(pk_local, sizeof(pk_local));
    return VIDX_OK;
}

vidx_status_t keypair_write(const char *path, const uint8_t *sk)
{
    // Sanity-check before writing.
    uint8_t pk[VIDX_ED25519_PK_LEN];
    vidx_status_t cs = vidx_ed25519_check_sk(sk, pk);
    secure_wipe(pk, sizeof(pk));
    if (cs != VIDX_OK) return cs;

    // Format as `[12,34,56,...]` — exactly the format solana-keygen produces.
    char buf[1024];
    size_t off = 0;
    buf[off++] = '[';
    for (size_t i = 0; i < VIDX_ED25519_SK_LEN; i++) {
        int w = snprintf(buf + off, sizeof(buf) - off,
                         "%u%s", (unsigned)sk[i],
                         i == VIDX_ED25519_SK_LEN - 1 ? "" : ",");
        if (w < 0 || (size_t)w >= sizeof(buf) - off) return VIDX_ERR_INTERNAL;
        off += (size_t)w;
    }
    if (off + 2 > sizeof(buf)) return VIDX_ERR_INTERNAL;
    buf[off++] = ']';
    buf[off++] = '\n';

    vidx_status_t s = write_file_atomic(path, (uint8_t *)buf, off, 0600);
    secure_wipe(buf, sizeof(buf));
    return s;
}

vidx_status_t pubkey_to_base58(const uint8_t pk[VIDX_ED25519_PK_LEN], char *out, size_t out_size)
{
    if (b58_encode(pk, VIDX_ED25519_PK_LEN, out, out_size) < 0) {
        return VIDX_ERR_INTERNAL;
    }
    return VIDX_OK;
}

vidx_status_t pubkey_from_base58(const char *s, uint8_t pk_out[VIDX_ED25519_PK_LEN])
{
    uint8_t buf[VIDX_ED25519_PK_LEN + 4];
    int n = b58_decode(s, buf, sizeof(buf));
    if (n != VIDX_ED25519_PK_LEN) {
        return VIDX_ERR_PARSE;
    }
    memcpy(pk_out, buf, VIDX_ED25519_PK_LEN);
    return VIDX_OK;
}
