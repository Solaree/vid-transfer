#ifndef VIDX_BUNDLE_H
#define VIDX_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

// Wire bundle format (plaintext, before sealed-box encryption):
//
//   "VIDX" magic        (4 bytes)
//   uint8 version       (1 byte, == 1)
//   uint8 flags         (1 byte)  bit0 = has tower
//   uint8 reserved[2]   (2 bytes, must be zero)
//   int64 timestamp     (8 bytes, big-endian unix seconds)
//   uint8 expected_pk[32]   (validator identity pubkey)
//   uint8 keypair[64]   (libsodium ed25519 secret key, seed||pk)
//   uint16 source_len   (big-endian)
//   uint8  source[]     (UTF-8 hostname / hint, ≤512 bytes)
//   uint16 tower_filename_len (big-endian; 0 if no tower)
//   uint8  tower_filename[]
//   uint32 tower_len    (big-endian; 0 if no tower)
//   uint8  tower[]
//
// Total max realistic size: ~256 KiB (cap enforced).

#define VIDX_BUNDLE_VERSION 1
#define VIDX_BUNDLE_FLAG_HAS_TOWER 0x01
#define VIDX_BUNDLE_MAGIC "VIDX"
#define VIDX_BUNDLE_MAGIC_LEN 4
#define VIDX_BUNDLE_HEAD_LEN  (4 + 1 + 1 + 2 + 8 + 32 + 64)

#define VIDX_BUNDLE_MAX_TOWER  (192 * 1024)
#define VIDX_BUNDLE_MAX_SOURCE 512
#define VIDX_BUNDLE_MAX_FNAME  255
#define VIDX_BUNDLE_MAX_TOTAL  (256 * 1024)

typedef struct {
    int64_t timestamp;
    uint8_t expected_pk[32];
    uint8_t keypair[64];           // SECRET — wipe after use
    char    source_hint[VIDX_BUNDLE_MAX_SOURCE + 1];
    char    tower_filename[VIDX_BUNDLE_MAX_FNAME + 1];
    uint8_t *tower;                // NULL if no tower
    size_t   tower_len;
} vidx_bundle_t;

void bundle_init(vidx_bundle_t *b);
void bundle_free(vidx_bundle_t *b);

// Allocate `*out` of the right length (heap), and serialize. Caller frees.
vidx_status_t bundle_encode(const vidx_bundle_t *b, uint8_t **out, size_t *out_len);

// Parse a bundle. The keypair field is copied into `b->keypair` directly;
// caller must call `bundle_free` to wipe.
vidx_status_t bundle_decode(const uint8_t *data, size_t len, vidx_bundle_t *b);

#endif
