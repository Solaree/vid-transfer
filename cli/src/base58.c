#include "base58.h"

#include <stdint.h>
#include <string.h>

static const char B58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t B58_REV[128] = {
    /* 0x00 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 0x10 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 0x20 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 0x30 */ -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    /* 0x40 */ -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    /* 0x50 */ 22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    /* 0x60 */ -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    /* 0x70 */ 47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

int b58_encode(const uint8_t *bin, size_t bin_len, char *out, size_t out_size)
{
    if (bin_len == 0) {
        if (out_size < 1) return -1;
        out[0] = '\0';
        return 0;
    }

    size_t zeroes = 0;
    while (zeroes < bin_len && bin[zeroes] == 0) zeroes++;

    // Worst-case size: ceil(log(256) / log(58) * n) ≈ n * 138/100 + 1
    size_t buf_len = bin_len * 138 / 100 + 1;
    uint8_t buf[256];
    if (buf_len > sizeof(buf)) return -1;
    memset(buf, 0, buf_len);

    size_t high = buf_len - 1;
    for (size_t i = zeroes; i < bin_len; i++) {
        unsigned int carry = bin[i];
        size_t j = buf_len - 1;
        while (1) {
            carry += (unsigned int)buf[j] * 256;
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
            if (j == 0 || (j <= high && carry == 0)) {
                if (j < high) high = j;
                break;
            }
            j--;
        }
    }

    size_t leading = high;
    while (leading < buf_len && buf[leading] == 0) leading++;

    size_t out_len = zeroes + (buf_len - leading);
    if (out_size < out_len + 1) return -1;

    char *p = out;
    for (size_t i = 0; i < zeroes; i++) *p++ = '1';
    for (size_t i = leading; i < buf_len; i++) *p++ = B58_ALPHABET[buf[i]];
    *p = '\0';
    return (int)out_len;
}

int b58_decode(const char *s, uint8_t *out, size_t out_size)
{
    if (!s) return -1;
    size_t len = strlen(s);
    if (len == 0) return 0;

    size_t zeroes = 0;
    while (zeroes < len && s[zeroes] == '1') zeroes++;

    size_t buf_len = len * 733 / 1000 + 1;
    uint8_t buf[256];
    if (buf_len > sizeof(buf)) return -1;
    memset(buf, 0, buf_len);

    size_t high = buf_len - 1;
    for (size_t i = zeroes; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 128) return -1;
        int v = B58_REV[c];
        if (v < 0) return -1;

        unsigned int carry = (unsigned int)v;
        size_t j = buf_len - 1;
        while (1) {
            carry += (unsigned int)buf[j] * 58;
            buf[j] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
            if (j == 0 || (j <= high && carry == 0)) {
                if (j < high) high = j;
                break;
            }
            j--;
        }
    }

    size_t leading = high;
    while (leading < buf_len && buf[leading] == 0) leading++;

    size_t out_len = zeroes + (buf_len - leading);
    if (out_size < out_len) return -1;

    uint8_t *p = out;
    for (size_t i = 0; i < zeroes; i++) *p++ = 0;
    for (size_t i = leading; i < buf_len; i++) *p++ = buf[i];
    return (int)out_len;
}
