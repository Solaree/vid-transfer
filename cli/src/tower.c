#define _POSIX_C_SOURCE 200809L

#include "tower.h"

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int tower_canonical_name(const char *identity_b58, char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "tower-1_9-%s.bin", identity_b58);
    if (n < 0 || (size_t)n >= out_size) return -1;
    return n;
}

vidx_status_t tower_locate(const char *ledger_dir,
                           const char *identity_b58,
                           char *out_path, size_t out_path_size,
                           bool *present)
{
    if (!ledger_dir || !identity_b58 || !out_path) return VIDX_ERR_USAGE;
    int n = snprintf(out_path, out_path_size,
                     "%s/tower-1_9-%s.bin", ledger_dir, identity_b58);
    if (n < 0 || (size_t)n >= out_path_size) return VIDX_ERR_INTERNAL;

    struct stat st;
    if (present) *present = (stat(out_path, &st) == 0 && S_ISREG(st.st_mode));
    return VIDX_OK;
}

vidx_status_t tower_read(const char *path, uint8_t **out, size_t *out_len)
{
    return read_file_all(path, out, out_len, 256 * 1024);
}

vidx_status_t tower_write(const char *path, const uint8_t *data, size_t len)
{
    return write_file_atomic(path, data, len, 0600);
}
