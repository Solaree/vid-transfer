#ifndef VIDX_PAIRING_H
#define VIDX_PAIRING_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define VIDX_PAIRING_WORDS    6
// 6 words × 11 bits/word = 66 bits.
//   - top 2 bits are zero padding (sanity-check on decode)
//   - low 64 bits carry the blake2b prefix of the recipient pubkey
//   - encoded as: <w0>-<w1>-<w2>-<w3>-<w4>-<w5>
//   - max length: 6 * 8 + 5 = 53 chars + NUL
#define VIDX_PAIRING_CODE_MAX 64

// Encode an 8-byte prefix into a hyphen-joined 6-word BIP39 string.
// `out` must be ≥ VIDX_PAIRING_CODE_MAX bytes.
vidx_status_t pairing_encode(const uint8_t prefix[8], char *out, size_t out_size);

// Decode a 6-word string into an 8-byte prefix. Words can be separated by
// any of: space, hyphen, underscore. Case-insensitive (BIP39 is lowercase).
// Returns VIDX_ERR_PARSE on bad input (wrong word count, unknown word, or
// non-zero padding bits).
vidx_status_t pairing_decode(const char *code, uint8_t prefix_out[8]);

#endif
