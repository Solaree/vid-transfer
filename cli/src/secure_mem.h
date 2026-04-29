#ifndef VIDX_SECURE_MEM_H
#define VIDX_SECURE_MEM_H

#include <stddef.h>

// Initialize libsodium and install a SIGINT/SIGTERM handler so we always
// get a chance to wipe live secret buffers before exiting.
int secure_init(void);

// Allocate / free a buffer that is mlocked and protected with guard pages
// (sodium_malloc). Use this for any buffer that holds key material.
void *secure_alloc(size_t n);
void  secure_free(void *p);

// Wipe a buffer (compiler cannot elide).
void secure_wipe(void *p, size_t n);

// Constant-time equality.
int  secure_eq(const void *a, const void *b, size_t n);

// Mark a region read-only / no-access (sodium_mprotect_readonly/noaccess).
// Useful immediately after writing the long-lived key, to prevent stray writes.
int  secure_readonly(void *p);
int  secure_readwrite(void *p);

// Track a live secret buffer so the signal handler can wipe + free it on Ctrl-C.
// All entries in the registry are wiped if the process receives SIGINT/SIGTERM.
// Returns 0 on success.
int  secure_register(void *p, size_t n);
void secure_unregister(void *p);

#endif
