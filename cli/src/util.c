#define _POSIX_C_SOURCE 200809L

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static log_level_t g_level = LOG_NORMAL;
static bool g_color = true;

#define C_RESET  "\x1b[0m"
#define C_BOLD   "\x1b[1m"
#define C_DIM    "\x1b[2m"
#define C_RED    "\x1b[31m"
#define C_GREEN  "\x1b[32m"
#define C_YELLOW "\x1b[33m"
#define C_BLUE   "\x1b[34m"
#define C_CYAN   "\x1b[36m"

void log_set_level(log_level_t level) { g_level = level; }
log_level_t log_get_level(void) { return g_level; }
bool log_color_enabled(void) { return g_color && isatty(STDERR_FILENO); }
void log_set_color(bool enabled) { g_color = enabled; }

void vlog(log_level_t lvl, const char *prefix, const char *color, const char *fmt, va_list ap)
{
    if (lvl > g_level) {
        return;
    }
    bool color_on = log_color_enabled();
    if (color_on) {
        fputs(color, stderr);
    }
    fputs(prefix, stderr);
    if (color_on) {
        fputs(C_RESET, stderr);
    }
    fputc(' ', stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_NORMAL, "[info]", C_BLUE, fmt, ap);
    va_end(ap);
}

void log_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_NORMAL, "[warn]", C_YELLOW, fmt, ap);
    va_end(ap);
}

void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_QUIET, "[error]", C_RED C_BOLD, fmt, ap);
    va_end(ap);
}

void log_debug(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_DEBUG, "[debug]", C_DIM, fmt, ap);
    va_end(ap);
}

void log_ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_NORMAL, "[ ok ]", C_GREEN, fmt, ap);
    va_end(ap);
}

void log_step(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog(LOG_NORMAL, "[step]", C_CYAN C_BOLD, fmt, ap);
    va_end(ap);
}

const char *vidx_status_str(vidx_status_t s) {
    switch (s) {
        case VIDX_OK: return "ok";
        case VIDX_ERR_USAGE: return "usage";
        case VIDX_ERR_IO: return "i/o";
        case VIDX_ERR_PERM: return "permission";
        case VIDX_ERR_PARSE: return "parse";
        case VIDX_ERR_CRYPTO: return "crypto";
        case VIDX_ERR_NETWORK: return "network";
        case VIDX_ERR_PROTOCOL: return "protocol";
        case VIDX_ERR_VERIFY: return "verify";
        case VIDX_ERR_TIMEOUT: return "timeout";
        case VIDX_ERR_RPC: return "rpc";
        case VIDX_ERR_USER_ABORT: return "user-abort";
        case VIDX_ERR_INTERNAL: return "internal";
    }
    return "unknown";
}

vidx_status_t read_file_all(const char *path, uint8_t **out_data, size_t *out_len, size_t max_size)
{
    *out_data = NULL;
    *out_len = 0;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_error("open(%s): %s", path, strerror(errno));
        return VIDX_ERR_IO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        log_error("fstat(%s): %s", path, strerror(errno));
        close(fd);
        return VIDX_ERR_IO;
    }
    if (!S_ISREG(st.st_mode)) {
        log_error("%s: not a regular file", path);
        close(fd);
        return VIDX_ERR_IO;
    }
    if ((size_t)st.st_size > max_size) {
        log_error("%s: file too large (%lld bytes, max %zu)",
                  path, (long long)st.st_size, max_size);
        close(fd);
        return VIDX_ERR_IO;
    }

    size_t len = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(len + 1);
    if (!buf) {
        close(fd);
        return VIDX_ERR_INTERNAL;
    }

    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            log_error("read(%s): %s", path, strerror(errno));
            free(buf);
            close(fd);
            return VIDX_ERR_IO;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';

    *out_data = buf;
    *out_len = got;
    return VIDX_OK;
}

vidx_status_t write_file_atomic(const char *path, const uint8_t *data, size_t len, mode_t mode)
{
    char tmp[4096];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return VIDX_ERR_IO;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        log_error("open(%s): %s", tmp, strerror(errno));
        return VIDX_ERR_IO;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t k = write(fd, data + off, len - off);
        if (k < 0) {
            if (errno == EINTR) continue;
            log_error("write(%s): %s", tmp, strerror(errno));
            close(fd); unlink(tmp);
            return VIDX_ERR_IO;
        }
        off += (size_t)k;
    }

    if (fsync(fd) != 0) {
        log_warn("fsync(%s): %s", tmp, strerror(errno));
        // Non-fatal: continue.
    }
    if (close(fd) != 0) {
        log_error("close(%s): %s", tmp, strerror(errno));
        unlink(tmp);
        return VIDX_ERR_IO;
    }

    if (chmod(tmp, mode) != 0) {
        log_warn("chmod(%s, %o): %s", tmp, mode, strerror(errno));
    }

    if (rename(tmp, path) != 0) {
        log_error("rename(%s -> %s): %s", tmp, path, strerror(errno));
        unlink(tmp);
        return VIDX_ERR_IO;
    }
    return VIDX_OK;
}

void to_hex(const uint8_t *bin, size_t bin_len, char *hex_out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < bin_len; i++) {
        hex_out[2*i]   = H[(bin[i] >> 4) & 0xF];
        hex_out[2*i+1] = H[bin[i] & 0xF];
    }
    hex_out[2*bin_len] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int from_hex(const char *hex, uint8_t *bin_out, size_t bin_max)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t bin_len = hex_len / 2;
    if (bin_len > bin_max) return -1;
    for (size_t i = 0; i < bin_len; i++) {
        int h = hex_nibble(hex[2*i]);
        int l = hex_nibble(hex[2*i+1]);
        if (h < 0 || l < 0) return -1;
        bin_out[i] = (uint8_t)((h << 4) | l);
    }
    return (int)bin_len;
}

size_t str_trim(char *s)
{
    if (!s) return 0;
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' '  || s[len-1] == '\t')) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (start < len && (s[start] == ' ' || s[start] == '\t')) {
        start++;
    }
    if (start > 0) {
        memmove(s, s + start, len - start + 1);
        len -= start;
    }
    return len;
}

ssize_t read_line(char *buf, size_t n)
{
    if (!fgets(buf, (int)n, stdin)) {
        return -1;
    }
    size_t l = str_trim(buf);
    return (ssize_t)l;
}

bool prompt_yes_no(const char *question, bool default_yes)
{
    char buf[16];
    fprintf(stderr, "%s %s ", question, default_yes ? "[Y/n]" : "[y/N]");
    fflush(stderr);
    if (read_line(buf, sizeof(buf)) < 0) return default_yes;
    if (buf[0] == '\0') return default_yes;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) { /* retry */ }
}
