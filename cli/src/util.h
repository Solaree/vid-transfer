#ifndef VIDX_UTIL_H
#define VIDX_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define VIDX_VERSION "0.1.0"

typedef enum {
    VIDX_OK = 0,
    VIDX_ERR_USAGE = 1,
    VIDX_ERR_IO = 2,
    VIDX_ERR_PERM = 3,
    VIDX_ERR_PARSE = 4,
    VIDX_ERR_CRYPTO = 5,
    VIDX_ERR_NETWORK = 6,
    VIDX_ERR_PROTOCOL = 7,
    VIDX_ERR_VERIFY = 8,
    VIDX_ERR_TIMEOUT = 9,
    VIDX_ERR_INTERNAL = 10,
    VIDX_ERR_RPC = 11,
    VIDX_ERR_USER_ABORT = 12
} vidx_status_t;

typedef enum {
    LOG_QUIET = 0,
    LOG_NORMAL = 1,
    LOG_VERBOSE = 2,
    LOG_DEBUG = 3
} log_level_t;

void log_set_level(log_level_t level);
log_level_t log_get_level(void);
bool log_color_enabled(void);
void log_set_color(bool enabled);

void vlog(log_level_t lvl, const char *prefix, const char *color, const char *fmt, va_list ap);
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_ok(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_step(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

const char *vidx_status_str(vidx_status_t s);

// Robust I/O helpers — used for non-secret data. For secrets, see secure_mem.
vidx_status_t read_file_all(const char *path, uint8_t **out_data, size_t *out_len, size_t max_size);
vidx_status_t write_file_atomic(const char *path, const uint8_t *data, size_t len, mode_t mode);

// Hex helpers (constant-time would be overkill here; not used for secrets).
void to_hex(const uint8_t *bin, size_t bin_len, char *hex_out);
int from_hex(const char *hex, uint8_t *bin_out, size_t bin_max);

// Trim trailing whitespace/newlines in-place. Returns new length.
size_t str_trim(char *s);

// Read a single line from stdin into buf (size n). Returns length, or -1 on EOF.
ssize_t read_line(char *buf, size_t n);
bool prompt_yes_no(const char *question, bool default_yes);

// Returns ms since epoch (monotonic-ish; used only for delays/timeouts).
int64_t now_ms(void);
void sleep_ms(int ms);

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#endif
