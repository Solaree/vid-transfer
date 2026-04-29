#include "pairing.h"

#include "bip39_wordlist.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

vidx_status_t pairing_encode(const uint8_t prefix[8], char *out, size_t out_size)
{
    // Build a 64-bit value (big-endian).
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | prefix[i];
    }
    // Pack into 66 bits with 2 bits of zero padding at the top.
    // word i takes bits [55-11i .. 55-11i+10]. We split a 66-bit value:
    //   bits 65,64 = 0 (pad)
    //   bits 63..0 = v
    // Word 0 takes the top 11 bits = bits [65..55] = (0<<9) | (v >> 55)
    // Word k takes bits [55-11k+10 .. 55-11k]  for k in 0..5 (with appropriate mask)
    // Implementation: build a 66-bit shift register and slice.

    int word_idx[VIDX_PAIRING_WORDS];
    for (int i = 0; i < VIDX_PAIRING_WORDS; i++) {
        int shift = 55 - 11 * i;
        uint64_t val;
        if (shift >= 0) {
            val = v >> shift;
        } else {
            val = v << (-shift);
        }
        word_idx[i] = (int)(val & 0x7FFu);
    }

    size_t pos = 0;
    for (int i = 0; i < VIDX_PAIRING_WORDS; i++) {
        const char *w = bip39_words[word_idx[i]];
        size_t wl = strlen(w);
        if (pos + wl + 2 >= out_size) return VIDX_ERR_INTERNAL;
        if (i > 0) out[pos++] = '-';
        memcpy(out + pos, w, wl);
        pos += wl;
    }
    out[pos] = '\0';
    return VIDX_OK;
}

vidx_status_t pairing_decode(const char *code, uint8_t prefix_out[8])
{
    if (!code) return VIDX_ERR_USAGE;

    char buf[VIDX_PAIRING_CODE_MAX];
    size_t cl = strlen(code);
    if (cl >= sizeof(buf)) return VIDX_ERR_PARSE;
    memcpy(buf, code, cl + 1);

    // Lowercase + normalize separators to single space.
    for (size_t i = 0; i < cl; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 'A' && c <= 'Z') buf[i] = (char)(c + 32);
        else if (c == '-' || c == '_' || c == '\t' || c == ',') buf[i] = ' ';
    }

    int word_idx[VIDX_PAIRING_WORDS];
    int found = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, " ", &save);
    while (tok && found < VIDX_PAIRING_WORDS) {
        if (*tok == '\0') { tok = strtok_r(NULL, " ", &save); continue; }
        int idx = bip39_word_index(tok);
        if (idx < 0) {
            log_error("pairing code: '%s' is not a BIP39 word", tok);
            return VIDX_ERR_PARSE;
        }
        word_idx[found++] = idx;
        tok = strtok_r(NULL, " ", &save);
    }
    // Make sure there are no extra tokens.
    if (found != VIDX_PAIRING_WORDS || (tok != NULL && *tok != '\0')) {
        // Walk through the rest to see if there really is a non-empty extra token.
        bool extra = false;
        while (tok) {
            if (*tok != '\0') { extra = true; break; }
            tok = strtok_r(NULL, " ", &save);
        }
        if (found != VIDX_PAIRING_WORDS || extra) {
            log_error("pairing code: expected %d words, got %d%s",
                      VIDX_PAIRING_WORDS, found, extra ? " (and extra tokens)" : "");
            return VIDX_ERR_PARSE;
        }
    }

    // Reassemble 66-bit value.
    // combined = (w0 << 55) | (w1 << 44) | ... | (w5 << 0)
    // Top 2 bits (positions 65,64) must be zero.
    uint64_t low = 0;     // bits [63..0]
    uint64_t high = 0;    // bits [65..64] (in low 2 bits of `high`)

    for (int i = 0; i < VIDX_PAIRING_WORDS; i++) {
        unsigned w = (unsigned)word_idx[i];
        int shift = 55 - 11 * i;
        if (shift >= 0) {
            // All 11 bits land in `low`, but bits above position 63 spill into high.
            // For i=0, shift=55 → bits [65..55] of combined.
            //   - bits 55..63 in low at positions 55..63 (top 9 bits of low) when shift+10 <= 63
            //   - bits 64..65 in high
            // Easiest: do it bit-by-bit.
            for (int b = 10; b >= 0; b--) {
                int bit = (int)((w >> b) & 1u);
                int pos = shift + b;  // position in 66-bit combined
                if (pos >= 64) {
                    high |= ((uint64_t)bit) << (pos - 64);
                } else {
                    low  |= ((uint64_t)bit) << pos;
                }
            }
        } else {
            // shift < 0 means we drop low bits — never happens with our layout, but
            // guard regardless.
            int drop = -shift;
            unsigned masked = w >> drop;
            low |= (uint64_t)masked;
        }
    }

    if (high != 0) {
        log_error("pairing code has nonzero high bits — likely a typo or wrong code");
        return VIDX_ERR_PARSE;
    }

    for (int i = 0; i < 8; i++) {
        prefix_out[i] = (uint8_t)((low >> (8 * (7 - i))) & 0xFF);
    }
    return VIDX_OK;
}
