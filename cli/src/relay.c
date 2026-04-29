#define _POSIX_C_SOURCE 200809L

#include "relay.h"

#include "crypto.h"
#include "util.h"

#include <curl/curl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int g_tls_strict = 1;
static int g_curl_inited = 0;

vidx_status_t relay_init(void)
{
    if (g_curl_inited) return VIDX_OK;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        log_error("curl_global_init failed");
        return VIDX_ERR_NETWORK;
    }
    g_curl_inited = 1;
    return VIDX_OK;
}

void relay_cleanup(void)
{
    if (g_curl_inited) {
        curl_global_cleanup();
        g_curl_inited = 0;
    }
}

void relay_set_tls_strict(int strict) { g_tls_strict = strict ? 1 : 0; }

struct buf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    size_t   limit;
};

static size_t buf_write(void *p, size_t sz, size_t nm, void *user)
{
    struct buf *b = (struct buf *)user;
    size_t n = sz * nm;
    if (b->len + n > b->limit) return 0; // exceed limit, abort transfer
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
        while (cap < b->len + n + 1) cap *= 2;
        uint8_t *nd = (uint8_t *)realloc(b->data, cap);
        if (!nd) return 0;
        b->data = nd;
        b->cap  = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

struct ro_reader {
    const uint8_t *data;
    size_t         len;
    size_t         off;
};

static size_t ro_read(void *p, size_t sz, size_t nm, void *user)
{
    struct ro_reader *r = (struct ro_reader *)user;
    size_t want = sz * nm;
    size_t avail = r->len - r->off;
    size_t n = avail < want ? avail : want;
    memcpy(p, r->data + r->off, n);
    r->off += n;
    return n;
}

static void apply_common(CURL *c)
{
    curl_easy_setopt(c, CURLOPT_USERAGENT, "vid-transfer/" VIDX_VERSION);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
    if (g_tls_strict) {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

static void hex_lower(const uint8_t *bin, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]   = H[(bin[i] >> 4) & 0xF];
        out[2*i+1] = H[bin[i] & 0xF];
    }
    out[2*n] = '\0';
}

// --- Minimal JSON helpers ----------------------------------------------------
//
// We do *not* build a full JSON parser — just tiny scanners for the few
// fields we read back from the relay.

// Skip whitespace.
static const char *json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

// Find a top-level "key" : ... in a JSON object string and return the value start.
static const char *json_find(const char *json, const char *key)
{
    if (!json) return NULL;
    size_t klen = strlen(key);
    const char *p = strchr(json, '{');
    if (!p) return NULL;
    p++;
    int depth = 1;
    while (*p && depth > 0) {
        p = json_skip_ws(p);
        if (*p == '"') {
            // key
            p++;
            const char *kstart = p;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            size_t key_seen_len = (size_t)(p - kstart);
            int matched = (key_seen_len == klen && memcmp(kstart, key, klen) == 0);
            if (*p == '"') p++;
            p = json_skip_ws(p);
            if (*p != ':') return NULL;
            p++;
            p = json_skip_ws(p);
            if (matched && depth == 1) return p;

            // Skip the value at this depth.
            // Rough scan: respect strings, count braces/brackets.
            int local_depth = 0;
            while (*p) {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
                    if (*p == '"') p++;
                    if (local_depth == 0) break;
                } else if (*p == '{' || *p == '[') {
                    local_depth++; p++;
                } else if (*p == '}' || *p == ']') {
                    if (local_depth == 0) break;
                    local_depth--; p++;
                } else if (*p == ',' && local_depth == 0) {
                    break;
                } else {
                    p++;
                }
            }
        } else if (*p == '}') {
            depth--; p++;
        } else if (*p == '{') {
            depth++; p++;
        } else if (*p == ',') {
            p++;
        } else if (*p == '\0') {
            break;
        } else {
            p++;
        }
    }
    return NULL;
}

static int json_extract_string(const char *value_start, char *out, size_t out_size)
{
    if (!value_start) return -1;
    const char *p = json_skip_ws(value_start);
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_size) {
        if (*p == '\\' && p[1]) {
            char e = p[1];
            char repl = 0;
            switch (e) {
                case 'n': repl = '\n'; break;
                case 't': repl = '\t'; break;
                case 'r': repl = '\r'; break;
                case '"': repl = '"';  break;
                case '\\': repl = '\\'; break;
                case '/': repl = '/'; break;
                default: repl = e; break;
            }
            out[i++] = repl;
            p += 2;
        } else {
            out[i++] = *p++;
        }
    }
    if (*p != '"') return -1;
    out[i] = '\0';
    return (int)i;
}

static int64_t json_extract_int(const char *value_start)
{
    if (!value_start) return -1;
    const char *p = json_skip_ws(value_start);
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (!end || end == p) return -1;
    return (int64_t)v;
}

// --- HTTP helpers ------------------------------------------------------------

static vidx_status_t do_request(const char *url, const char *method,
                                const struct curl_slist *headers,
                                const uint8_t *body, size_t body_len,
                                long *out_status,
                                struct buf *resp,
                                long timeout_sec)
{
    CURL *c = curl_easy_init();
    if (!c) return VIDX_ERR_INTERNAL;
    apply_common(c);

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_sec);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, buf_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, resp);

    struct ro_reader reader = { .data = body, .len = body_len, .off = 0 };

    if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    } else if (strcmp(method, "PUT") == 0) {
        curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(c, CURLOPT_PUT, 1L);
        curl_easy_setopt(c, CURLOPT_READFUNCTION, ro_read);
        curl_easy_setopt(c, CURLOPT_READDATA, &reader);
        curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t)body_len);
    } else {
        curl_easy_cleanup(c);
        return VIDX_ERR_USAGE;
    }

    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        log_error("HTTP %s %s failed: %s", method, url, curl_easy_strerror(rc));
        curl_easy_cleanup(c);
        return rc == CURLE_OPERATION_TIMEDOUT ? VIDX_ERR_TIMEOUT : VIDX_ERR_NETWORK;
    }

    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    *out_status = http_code;

    log_debug("HTTP %s %s -> %ld (%zu bytes)", method, url, http_code, resp->len);
    curl_easy_cleanup(c);
    return VIDX_OK;
}

static void buf_free(struct buf *b)
{
    if (b && b->data) {
        sodium_memzero(b->data, b->len);
        free(b->data);
        b->data = NULL;
        b->len = b->cap = 0;
    }
}

vidx_status_t relay_health(const char *base_url)
{
    char url[1024];
    if (snprintf(url, sizeof(url), "%s/healthz", base_url) >= (int)sizeof(url)) {
        return VIDX_ERR_USAGE;
    }
    struct buf resp = { .limit = 4096 };
    struct curl_slist *h = curl_slist_append(NULL, "Accept: application/json");
    long status = 0;
    vidx_status_t s = do_request(url, "GET", h, NULL, 0, &status, &resp, 10);
    curl_slist_free_all(h);
    buf_free(&resp);
    if (s != VIDX_OK) return s;
    if (status != 200) {
        log_error("relay healthz returned %ld", status);
        return VIDX_ERR_PROTOCOL;
    }
    return VIDX_OK;
}

vidx_status_t relay_create_session(const char *base_url,
                                   const uint8_t prefix[8],
                                   const uint8_t recipient_pubkey[32],
                                   int64_t *out_expires_at)
{
    char url[1024];
    if (snprintf(url, sizeof(url), "%s/v1/sessions", base_url) >= (int)sizeof(url)) {
        return VIDX_ERR_USAGE;
    }

    char prefix_hex[17];
    char pk_hex[65];
    hex_lower(prefix, 8, prefix_hex);
    hex_lower(recipient_pubkey, 32, pk_hex);

    char body[512];
    int n = snprintf(body, sizeof(body),
        "{\"prefix\":\"%s\",\"recipientPubkey\":\"%s\",\"version\":1}",
        prefix_hex, pk_hex);
    if (n < 0 || (size_t)n >= sizeof(body)) return VIDX_ERR_INTERNAL;

    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: application/json");
    h = curl_slist_append(h, "Accept: application/json");

    struct buf resp = { .limit = 16 * 1024 };
    long status = 0;
    vidx_status_t s = do_request(url, "POST", h, (uint8_t *)body, (size_t)n, &status, &resp, 15);
    curl_slist_free_all(h);
    if (s != VIDX_OK) { buf_free(&resp); return s; }

    if (status == 409) {
        log_error("relay reports prefix collision (someone else is paired with the same prefix). "
                  "Re-run the receiver to generate a fresh keypair.");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }
    if (status != 200 && status != 201) {
        log_error("relay create_session: HTTP %ld; body: %.*s",
                  status, (int)resp.len, resp.data ? (char*)resp.data : "");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }

    if (out_expires_at) {
        const char *v = json_find((const char *)resp.data, "expiresAt");
        int64_t exp = json_extract_int(v);
        *out_expires_at = exp > 0 ? exp : 0;
    }
    buf_free(&resp);
    return VIDX_OK;
}

vidx_status_t relay_get_session_pubkey(const char *base_url,
                                       const uint8_t prefix[8],
                                       uint8_t recipient_pubkey_out[32],
                                       int64_t *out_expires_at)
{
    char prefix_hex[17];
    hex_lower(prefix, 8, prefix_hex);

    char url[1024];
    if (snprintf(url, sizeof(url), "%s/v1/sessions/%s", base_url, prefix_hex)
        >= (int)sizeof(url)) {
        return VIDX_ERR_USAGE;
    }

    struct curl_slist *h = curl_slist_append(NULL, "Accept: application/json");
    struct buf resp = { .limit = 16 * 1024 };
    long status = 0;
    vidx_status_t s = do_request(url, "GET", h, NULL, 0, &status, &resp, 15);
    curl_slist_free_all(h);
    if (s != VIDX_OK) { buf_free(&resp); return s; }

    if (status == 404) {
        log_error("relay session not found (expired or never created). Ask the receiver to start a new pairing.");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }
    if (status != 200) {
        log_error("relay get_session: HTTP %ld; body: %.*s",
                  status, (int)resp.len, resp.data ? (char*)resp.data : "");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }

    char pk_hex[128];
    const char *v = json_find((const char *)resp.data, "recipientPubkey");
    int n = json_extract_string(v, pk_hex, sizeof(pk_hex));
    if (n != 64) {
        log_error("relay returned malformed recipientPubkey");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }
    uint8_t pk[32];
    if (from_hex(pk_hex, pk, sizeof(pk)) != 32) {
        log_error("relay returned non-hex recipientPubkey");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }

    // CRITICAL: re-derive the prefix locally and confirm it matches what the
    // user typed in. If a malicious relay swaps in a different pubkey, this
    // mismatch is what saves us.
    uint8_t derived[8];
    if (vidx_pair_hash(pk, 32, derived) != VIDX_OK) {
        buf_free(&resp);
        return VIDX_ERR_CRYPTO;
    }
    if (memcmp(derived, prefix, 8) != 0) {
        log_error("PAIRING MISMATCH: relay returned a pubkey whose hash does not match "
                  "the pairing code. This means the relay is malicious or compromised. "
                  "Aborting.");
        buf_free(&resp);
        return VIDX_ERR_VERIFY;
    }

    memcpy(recipient_pubkey_out, pk, 32);

    if (out_expires_at) {
        const char *vexp = json_find((const char *)resp.data, "expiresAt");
        int64_t exp = json_extract_int(vexp);
        *out_expires_at = exp > 0 ? exp : 0;
    }

    buf_free(&resp);
    return VIDX_OK;
}

vidx_status_t relay_put_ciphertext(const char *base_url,
                                   const uint8_t prefix[8],
                                   const uint8_t *ct, size_t ct_len)
{
    char prefix_hex[17];
    hex_lower(prefix, 8, prefix_hex);

    char url[1024];
    if (snprintf(url, sizeof(url), "%s/v1/sessions/%s/ciphertext", base_url, prefix_hex)
        >= (int)sizeof(url)) {
        return VIDX_ERR_USAGE;
    }

    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: application/octet-stream");
    h = curl_slist_append(h, "Accept: application/json");

    struct buf resp = { .limit = 16 * 1024 };
    long status = 0;
    vidx_status_t s = do_request(url, "PUT", h, ct, ct_len, &status, &resp, 60);
    curl_slist_free_all(h);
    if (s != VIDX_OK) { buf_free(&resp); return s; }

    if (status == 409) {
        log_error("relay rejected ciphertext upload (already received once). Pairing was used.");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }
    if (status == 413) {
        log_error("relay rejected ciphertext: payload too large.");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }
    if (status != 200 && status != 201 && status != 204) {
        log_error("relay put_ciphertext: HTTP %ld; body: %.*s",
                  status, (int)resp.len, resp.data ? (char*)resp.data : "");
        buf_free(&resp);
        return VIDX_ERR_PROTOCOL;
    }

    buf_free(&resp);
    return VIDX_OK;
}

vidx_status_t relay_wait_ciphertext(const char *base_url,
                                    const uint8_t prefix[8],
                                    int timeout_ms,
                                    uint8_t **out_ct, size_t *out_len)
{
    char prefix_hex[17];
    hex_lower(prefix, 8, prefix_hex);

    char url[1024];
    if (snprintf(url, sizeof(url), "%s/v1/sessions/%s/ciphertext?wait=1",
                 base_url, prefix_hex) >= (int)sizeof(url)) {
        return VIDX_ERR_USAGE;
    }

    int64_t deadline = now_ms() + timeout_ms;
    int attempt = 0;
    while (1) {
        struct curl_slist *h = curl_slist_append(NULL, "Accept: application/octet-stream");
        struct buf resp = { .limit = 4 * 1024 * 1024 }; // 4 MiB ceiling
        long status = 0;

        long per_call = (long)((deadline - now_ms()) / 1000) + 1;
        if (per_call > 30) per_call = 30; // cap each long-poll
        if (per_call < 5)  per_call = 5;

        vidx_status_t s = do_request(url, "GET", h, NULL, 0, &status, &resp, per_call);
        curl_slist_free_all(h);

        if (s == VIDX_OK && status == 200 && resp.len > 0) {
            *out_ct = resp.data;
            *out_len = resp.len;
            return VIDX_OK;
        }

        // 204 = "no content yet" — keep polling. 404 = session expired.
        if (s == VIDX_OK && status == 404) {
            log_error("session expired before sender uploaded.");
            buf_free(&resp);
            return VIDX_ERR_TIMEOUT;
        }
        if (s != VIDX_OK && s != VIDX_ERR_TIMEOUT) {
            buf_free(&resp);
            return s;
        }

        buf_free(&resp);

        if (now_ms() >= deadline) {
            return VIDX_ERR_TIMEOUT;
        }

        // Back-off slightly between polls to be polite.
        int sleep_for = 500 + attempt * 250;
        if (sleep_for > 2000) sleep_for = 2000;
        sleep_ms(sleep_for);
        attempt++;
    }
}
