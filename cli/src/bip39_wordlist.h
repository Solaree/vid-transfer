#ifndef VIDX_BIP39_WORDLIST_H
#define VIDX_BIP39_WORDLIST_H

#include <stddef.h>

#define BIP39_WORD_COUNT 2048

extern const char *const bip39_words[BIP39_WORD_COUNT];

// Linear search; returns the index 0..2047 or -1 on miss.
int bip39_word_index(const char *word);

#endif
