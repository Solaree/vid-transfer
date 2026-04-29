#include "bundle.h"

#include "secure_mem.h"
#include "util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static void put_u16(uint8_t *p, uint16_t v) { p[0] = (v >> 8) & 0xFF; p[1] = v & 0xFF; }
static void put_u32(uint8_t *p, uint32_t v) { p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF; }
static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (v >> (56 - 8*i)) & 0xFF; }
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get_u32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

void bundle_init(vidx_bundle_t *b) { memset(b, 0, sizeof(*b)); }

void bundle_free(vidx_bundle_t *b)
{
    if (!b) return;
    sodium_memzero(b->keypair, sizeof(b->keypair));
    if (b->tower) {
        sodium_memzero(b->tower, b->tower_len);
        free(b->tower);
        b->tower = NULL;
    }
    sodium_memzero(b, sizeof(*b));
}

vidx_status_t bundle_encode(const vidx_bundle_t *b, uint8_t **out, size_t *out_len)
{
    size_t source_len = strnlen(b->source_hint, VIDX_BUNDLE_MAX_SOURCE);
    size_t fname_len  = strnlen(b->tower_filename, VIDX_BUNDLE_MAX_FNAME);
    bool   has_tower  = (b->tower && b->tower_len > 0);

    if (has_tower && b->tower_len > VIDX_BUNDLE_MAX_TOWER) {
        log_error("tower too large: %zu bytes (max %d)", b->tower_len, VIDX_BUNDLE_MAX_TOWER);
        return VIDX_ERR_USAGE;
    }
    if (!has_tower) fname_len = 0;

    size_t total = VIDX_BUNDLE_HEAD_LEN
                 + 2 + source_len
                 + 2 + fname_len
                 + 4 + (has_tower ? b->tower_len : 0);
    if (total > VIDX_BUNDLE_MAX_TOTAL) {
        log_error("bundle too large: %zu", total);
        return VIDX_ERR_USAGE;
    }

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return VIDX_ERR_INTERNAL;
    size_t off = 0;

    memcpy(buf + off, VIDX_BUNDLE_MAGIC, VIDX_BUNDLE_MAGIC_LEN); off += VIDX_BUNDLE_MAGIC_LEN;
    buf[off++] = VIDX_BUNDLE_VERSION;
    buf[off++] = (uint8_t)(has_tower ? VIDX_BUNDLE_FLAG_HAS_TOWER : 0);
    buf[off++] = 0;
    buf[off++] = 0;
    put_u64(buf + off, (uint64_t)b->timestamp); off += 8;
    memcpy(buf + off, b->expected_pk, 32); off += 32;
    memcpy(buf + off, b->keypair, 64); off += 64;

    put_u16(buf + off, (uint16_t)source_len); off += 2;
    if (source_len) { memcpy(buf + off, b->source_hint, source_len); off += source_len; }

    put_u16(buf + off, (uint16_t)fname_len); off += 2;
    if (fname_len)  { memcpy(buf + off, b->tower_filename, fname_len); off += fname_len; }

    put_u32(buf + off, (uint32_t)(has_tower ? b->tower_len : 0)); off += 4;
    if (has_tower)  { memcpy(buf + off, b->tower, b->tower_len); off += b->tower_len; }

    *out = buf;
    *out_len = off;
    return VIDX_OK;
}

vidx_status_t bundle_decode(const uint8_t *data, size_t len, vidx_bundle_t *b)
{
    bundle_init(b);
    if (len < VIDX_BUNDLE_HEAD_LEN) {
        log_error("bundle too short: %zu bytes", len);
        return VIDX_ERR_PARSE;
    }
    if (memcmp(data, VIDX_BUNDLE_MAGIC, VIDX_BUNDLE_MAGIC_LEN) != 0) {
        log_error("bundle magic mismatch");
        return VIDX_ERR_PARSE;
    }
    size_t off = VIDX_BUNDLE_MAGIC_LEN;
    uint8_t version = data[off++];
    if (version != VIDX_BUNDLE_VERSION) {
        log_error("bundle version %u not supported (this build supports %u)",
                  version, VIDX_BUNDLE_VERSION);
        return VIDX_ERR_PARSE;
    }
    uint8_t flags = data[off++];
    if (data[off] != 0 || data[off+1] != 0) {
        log_error("bundle reserved bytes nonzero");
        return VIDX_ERR_PARSE;
    }
    off += 2;
    b->timestamp = (int64_t)get_u64(data + off); off += 8;
    memcpy(b->expected_pk, data + off, 32); off += 32;
    memcpy(b->keypair, data + off, 64); off += 64;

    if (off + 2 > len) goto trunc;
    uint16_t source_len = get_u16(data + off); off += 2;
    if (source_len > VIDX_BUNDLE_MAX_SOURCE || off + source_len > len) goto trunc;
    if (source_len) memcpy(b->source_hint, data + off, source_len);
    b->source_hint[source_len] = '\0';
    off += source_len;

    if (off + 2 > len) goto trunc;
    uint16_t fname_len = get_u16(data + off); off += 2;
    if (fname_len > VIDX_BUNDLE_MAX_FNAME || off + fname_len > len) goto trunc;
    if (fname_len) memcpy(b->tower_filename, data + off, fname_len);
    b->tower_filename[fname_len] = '\0';
    off += fname_len;

    if (off + 4 > len) goto trunc;
    uint32_t tower_len = get_u32(data + off); off += 4;
    if (tower_len > VIDX_BUNDLE_MAX_TOWER || off + tower_len > len) goto trunc;

    if (tower_len > 0) {
        if ((flags & VIDX_BUNDLE_FLAG_HAS_TOWER) == 0) {
            log_warn("tower bytes present but flag is unset; treating as present");
        }
        b->tower = (uint8_t *)malloc(tower_len);
        if (!b->tower) {
            bundle_free(b);
            return VIDX_ERR_INTERNAL;
        }
        memcpy(b->tower, data + off, tower_len);
        b->tower_len = tower_len;
        off += tower_len;
    } else if (flags & VIDX_BUNDLE_FLAG_HAS_TOWER) {
        log_warn("tower flag set but tower length is zero");
    }

    if (off != len) {
        log_warn("bundle has %zu trailing bytes; ignored", len - off);
    }
    return VIDX_OK;

trunc:
    log_error("bundle truncated at offset %zu (len=%zu)", off, len);
    bundle_free(b);
    return VIDX_ERR_PARSE;
}
