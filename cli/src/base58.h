#ifndef VIDX_BASE58_H
#define VIDX_BASE58_H

#include <stddef.h>
#include <stdint.h>

// Bitcoin / Solana base58 alphabet. Encode `bin` of length `bin_len` into
// `out` (caller-allocated, at least `bin_len * 138 / 100 + 2` bytes including
// the trailing NUL). Returns the number of characters written (excluding NUL),
// or -1 on overflow.
int b58_encode(const uint8_t *bin, size_t bin_len, char *out, size_t out_size);

// Decode `s` into `out`. Returns the number of bytes written, or -1 on
// invalid input or overflow.
int b58_decode(const char *s, uint8_t *out, size_t out_size);

#endif
