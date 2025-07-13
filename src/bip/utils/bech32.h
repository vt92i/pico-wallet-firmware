#pragma once

#include <stddef.h>
#include <stdint.h>

#define BECH32_MAX_HRP_LEN  (83)  // Maximum length of Human Readable Part (HRP)
#define BECH32_MAX_DATA_LEN (90)  // Maximum length of data part (excluding checksum)
#define BECH32_MAX_STRING_LEN \
  (BECH32_MAX_HRP_LEN + 1 + BECH32_MAX_DATA_LEN + 6)  // Maximum length of the full Bech32 string

int bech32_encode(const char *hrp, const uint8_t *data, size_t data_len, char *output);
int bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input);

int convert_bits(uint8_t *out, size_t *out_len, int to_bits, int from_bits, const uint8_t *in, size_t in_len, int pad);
