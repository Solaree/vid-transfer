#define _POSIX_C_SOURCE 200809L

#include "solana_rpc.h"

#include "util.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rpc_buf {
    char  *data;
    size_t len;
    size_t cap;
    size_t limit;
};

static size_t rpc_write(void *p, size_t sz, size_t nm, void *user)
{
    struct rpc_buf *b = (struct rpc_buf *)user;
    size_t n = sz * nm;
    if (b->len + n > b->limit) return 0;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1) cap *= 2;
        char *nd = (char *)realloc(b->data, cap);
        if (!nd) return 0;
        b->data = nd;
        b->cap  = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static const char *json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

// Crude scanner: returns a pointer to the value after `"key":`. Operates on
// the entire buffer; works because field names in Solana RPC responses are
// uniquely identifiable for our purposes.
static const char *json_find_anywhere(const char *json, const char *key)
{
    if (!json || !key) return NULL;
    size_t klen = strlen(key);
    const char *p = json;
    while ((p = strchr(p, '"')) != NULL) {
        const char *kstart = p + 1;
        const char *kend = strchr(kstart, '"');
        if (!kend) return NULL;
        size_t found_len = (size_t)(kend - kstart);
        if (found_len == klen && memcmp(kstart, key, klen) == 0) {
            const char *q = json_skip_ws(kend + 1);
            if (*q == ':') {
                return json_skip_ws(q + 1);
            }
        }
        p = kend + 1;
    }
    return NULL;
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

static int json_extract_string(const char *value_start, char *out, size_t out_size)
{
    if (!value_start) return -1;
    const char *p = json_skip_ws(value_start);
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_size) {
        if (*p == '\\' && p[1]) {
            out[i++] = p[1];
            p += 2;
        } else {
            out[i++] = *p++;
        }
    }
    if (*p != '"') return -1;
    out[i] = '\0';
    return (int)i;
}

static vidx_status_t rpc_call(const char *url,
                              const char *body,
                              struct rpc_buf *resp,
                              long timeout)
{
    CURL *c = curl_easy_init();
    if (!c) return VIDX_ERR_INTERNAL;

    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: application/json");
    h = curl_slist_append(h, "Accept: application/json");

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "vid-transfer/" VIDX_VERSION);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, rpc_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, resp);

    CURLcode rc = curl_easy_perform(c);
    long http = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK) {
        log_error("RPC %s failed: %s", url, curl_easy_strerror(rc));
        return rc == CURLE_OPERATION_TIMEDOUT ? VIDX_ERR_TIMEOUT : VIDX_ERR_NETWORK;
    }
    if (http != 200) {
        log_error("RPC %s returned HTTP %ld", url, http);
        return VIDX_ERR_RPC;
    }
    if (!resp->data || resp->len == 0) {
        log_error("RPC %s returned empty body", url);
        return VIDX_ERR_RPC;
    }
    if (json_find_anywhere(resp->data, "error")) {
        log_error("RPC error: %.*s", (int)resp->len, resp->data);
        return VIDX_ERR_RPC;
    }
    return VIDX_OK;
}

vidx_status_t solana_get_epoch_info(const char *rpc_url, solana_epoch_info_t *out)
{
    if (!out) return VIDX_ERR_USAGE;
    memset(out, 0, sizeof(*out));

    const char *body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getEpochInfo\"}";
    struct rpc_buf resp = { .limit = 64 * 1024 };
    vidx_status_t s = rpc_call(rpc_url, body, &resp, 30);
    if (s != VIDX_OK) { free(resp.data); return s; }

    int64_t v;
    v = json_extract_int(json_find_anywhere(resp.data, "epoch"));
    if (v < 0) { free(resp.data); return VIDX_ERR_RPC; }
    out->epoch = (uint64_t)v;

    v = json_extract_int(json_find_anywhere(resp.data, "slotIndex"));
    if (v < 0) { free(resp.data); return VIDX_ERR_RPC; }
    out->slot_index = (uint64_t)v;

    v = json_extract_int(json_find_anywhere(resp.data, "slotsInEpoch"));
    if (v < 0) { free(resp.data); return VIDX_ERR_RPC; }
    out->slots_in_epoch = (uint64_t)v;

    v = json_extract_int(json_find_anywhere(resp.data, "absoluteSlot"));
    if (v < 0) { free(resp.data); return VIDX_ERR_RPC; }
    out->absolute_slot = (uint64_t)v;

    free(resp.data);
    return VIDX_OK;
}

vidx_status_t solana_get_version(const char *rpc_url, char *out_version, size_t out_size)
{
    const char *body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVersion\"}";
    struct rpc_buf resp = { .limit = 64 * 1024 };
    vidx_status_t s = rpc_call(rpc_url, body, &resp, 15);
    if (s != VIDX_OK) { free(resp.data); return s; }

    int n = json_extract_string(json_find_anywhere(resp.data, "solana-core"),
                                out_version, out_size);
    free(resp.data);
    if (n < 0) {
        snprintf(out_version, out_size, "unknown");
    }
    return VIDX_OK;
}

vidx_status_t solana_get_vote_account_by_identity(const char *rpc_url,
                                                  const char *identity_b58,
                                                  solana_vote_account_t *out)
{
    if (!out) return VIDX_ERR_USAGE;
    memset(out, 0, sizeof(*out));

    const char *body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVoteAccounts\"}";
    struct rpc_buf resp = { .limit = 16 * 1024 * 1024 };
    vidx_status_t s = rpc_call(rpc_url, body, &resp, 30);
    if (s != VIDX_OK) { free(resp.data); return s; }

    // Walk both `current` and `delinquent` arrays for any object whose
    // "nodePubkey" matches identity_b58. We do this with a substring scan
    // since the JSON shape is a fixed array of objects with these keys.

    const char *p = resp.data;
    size_t id_len = strlen(identity_b58);
    bool found = false;

    // Find each occurrence of the identity in the doc and check if it's a nodePubkey value.
    while ((p = strstr(p, identity_b58)) != NULL) {
        // Walk back to find the nearest "nodePubkey":"
        const char *back = p;
        const char *NP = "\"nodePubkey\":\"";
        size_t NP_len = strlen(NP);

        // Look back up to ~64 chars for the field marker.
        const char *probe = (back - NP_len >= resp.data) ? back - NP_len : resp.data;
        if (memcmp(probe, NP, NP_len) == 0 &&
            // exact match (closing quote follows the id)
            p[id_len] == '"') {

            // Find the surrounding object by walking back to '{' at depth 0.
            const char *obj_start = p;
            int depth = 0;
            while (obj_start > resp.data) {
                if (*obj_start == '}') depth++;
                else if (*obj_start == '{') {
                    if (depth == 0) break;
                    depth--;
                }
                obj_start--;
            }
            // Find end of object.
            const char *obj_end = p;
            depth = 0;
            while (*obj_end) {
                if (*obj_end == '{') depth++;
                else if (*obj_end == '}') {
                    if (depth == 0) break;
                    depth--;
                }
                obj_end++;
            }

            // Determine whether we're inside `current` or `delinquent`.
            // Heuristic: search backwards for `"current":[` vs `"delinquent":[`.
            // The closer marker wins.
            size_t pos = (size_t)(p - resp.data);
            const char *cur = strstr(resp.data, "\"current\":[");
            const char *del = strstr(resp.data, "\"delinquent\":[");
            bool is_current = false;
            if (cur && del) {
                size_t cur_pos = (size_t)(cur - resp.data);
                size_t del_pos = (size_t)(del - resp.data);
                if (cur_pos < pos && (del_pos > pos || cur_pos > del_pos)) is_current = true;
            } else if (cur && (size_t)(cur - resp.data) < pos) {
                is_current = true;
            }
            out->is_current = is_current;
            out->present = true;

            // Extract values from this object. We can search inside the slice.
            char tmp[256];
            // Make a NUL-terminated slice copy for scanning.
            size_t len = (size_t)(obj_end - obj_start);
            if (len > sizeof(tmp) - 1) len = sizeof(tmp) - 1;
            memcpy(tmp, obj_start, len);
            tmp[len] = '\0';

            int64_t iv;

            iv = json_extract_int(json_find_anywhere(tmp, "activatedStake"));
            if (iv >= 0) out->activated_stake = (uint64_t)iv;

            iv = json_extract_int(json_find_anywhere(tmp, "commission"));
            if (iv >= 0) out->commission = (uint64_t)iv;

            iv = json_extract_int(json_find_anywhere(tmp, "lastVote"));
            if (iv >= 0) out->last_vote = (uint64_t)iv;

            iv = json_extract_int(json_find_anywhere(tmp, "rootSlot"));
            if (iv >= 0) out->root_slot = (uint64_t)iv;

            json_extract_string(json_find_anywhere(tmp, "votePubkey"),
                                out->vote_pubkey, sizeof(out->vote_pubkey));
            json_extract_string(json_find_anywhere(tmp, "nodePubkey"),
                                out->node_pubkey, sizeof(out->node_pubkey));

            found = true;
            break;
        }
        p++;
    }

    free(resp.data);
    if (!found) {
        out->present = false;
    }
    return VIDX_OK;
}

vidx_status_t solana_get_leader_summary(const char *rpc_url,
                                        const char *identity_b58,
                                        solana_leader_summary_t *out)
{
    if (!out) return VIDX_ERR_USAGE;
    memset(out, 0, sizeof(*out));

    solana_epoch_info_t ei;
    vidx_status_t s = solana_get_epoch_info(rpc_url, &ei);
    if (s != VIDX_OK) return s;
    uint64_t epoch_first_slot = ei.absolute_slot - ei.slot_index;

    // getLeaderSchedule with identity filter returns only that node's slots
    // (relative to the start of the epoch).
    char body[512];
    int n = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLeaderSchedule\","
        "\"params\":[null,{\"identity\":\"%s\"}]}", identity_b58);
    if (n < 0 || (size_t)n >= sizeof(body)) return VIDX_ERR_INTERNAL;

    struct rpc_buf resp = { .limit = 16 * 1024 * 1024 };
    s = rpc_call(rpc_url, body, &resp, 60);
    if (s != VIDX_OK) { free(resp.data); return s; }

    // Response shape: { result: { "<identity>": [slot_idx, ...] } }
    // We scan the array of integers.
    const char *id_field = strstr(resp.data, identity_b58);
    if (!id_field) {
        // Validator has no leader slots in this epoch — fine.
        free(resp.data);
        return VIDX_OK;
    }
    const char *arr = strchr(id_field, '[');
    if (!arr) { free(resp.data); return VIDX_OK; }
    arr++;

    uint64_t total = 0;
    uint64_t next_slot = 0;
    bool has_next = false;
    uint64_t cur_slot = ei.absolute_slot;

    const char *p = arr;
    while (*p && *p != ']') {
        while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\t') p++;
        if (*p == ']') break;
        char *end = NULL;
        long long v = strtoll(p, &end, 10);
        if (!end || end == p) break;
        uint64_t abs = epoch_first_slot + (uint64_t)v;
        total++;
        if (abs >= cur_slot && (!has_next || abs < next_slot)) {
            next_slot = abs;
            has_next = true;
        }
        p = end;
    }

    out->total_leader_slots = total;
    out->next_leader_slot = next_slot;
    out->has_next = has_next;
    out->slots_until_next = has_next ? (next_slot - cur_slot) : 0;

    free(resp.data);
    return VIDX_OK;
}
