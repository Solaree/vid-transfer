#ifndef VIDX_TOWER_H
#define VIDX_TOWER_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

// Conventional Solana tower filename pattern. The Agave validator writes
// tower files named: tower-1_9-<identity_pubkey_base58>.bin
//
// Build the canonical name into `out` (>= 96 bytes). Returns the length, or
// -1 on overflow.
int tower_canonical_name(const char *identity_b58, char *out, size_t out_size);

// Resolve the tower file path inside `ledger_dir` for `identity_b58`. Sets
// `*present` to true if the file exists. `out` (path) must be ≥ 4096 bytes.
vidx_status_t tower_locate(const char *ledger_dir,
                           const char *identity_b58,
                           char *out_path, size_t out_path_size,
                           bool *present);

// Load the tower file into a heap buffer (caller frees).
vidx_status_t tower_read(const char *path, uint8_t **out, size_t *out_len);

// Write a tower file with 0600 perms, atomically.
vidx_status_t tower_write(const char *path, const uint8_t *data, size_t len);

#endif
