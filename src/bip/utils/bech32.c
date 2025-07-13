#include "bech32.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

static const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int8_t charset_lut[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17,
    21, 20, 26, 30, 7,  5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27,
    19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,
    23, -1, 18, 22, 31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

static uint32_t polymod(const uint8_t *values, size_t length) {
  uint32_t chk = 1;
  for (size_t i = 0; i < length; i++) {
    uint8_t top = (uint8_t)(chk >> 25);
    chk = (chk & 0x1FFFFFF) << 5 ^ values[i];
    if (top & 1) chk ^= 0X3B6A57B2;
    if (top & 2) chk ^= 0X26508E6D;
    if (top & 4) chk ^= 0X1EA119FA;
    if (top & 8) chk ^= 0X3D4233DD;
    if (top & 16) chk ^= 0X2A1462B3;
  }
  return chk;
}

static void hrp_expand(const char *hrp, uint8_t *output) {
  size_t len = strlen(hrp);
  for (size_t i = 0; i < len; i++) output[i] = hrp[i] >> 5;
  output[len] = 0;
  for (size_t i = 0; i < len; i++) output[len + 1 + i] = hrp[i] & 0x1F;
}

static void create_checksum(const char *hrp, const uint8_t *data, size_t data_len, uint8_t *checksum_output) {
  uint8_t buf[BECH32_MAX_HRP_LEN * 2 + 1 + BECH32_MAX_DATA_LEN + 6];
  hrp_expand(hrp, buf);
  size_t prefix_len = strlen(hrp) * 2 + 1;
  memcpy(buf + prefix_len, data, data_len);
  memset(buf + prefix_len + data_len, 0, 6);
  uint32_t mod = polymod(buf, prefix_len + data_len + 6) ^ 1;
  for (size_t i = 0; i < 6; i++) checksum_output[i] = (mod >> (5 * (5 - i))) & 0x1F;
}

int bech32_encode(const char *hrp, const uint8_t *data, size_t data_len, char *output) {
  if (!output || !hrp || !data || data_len > BECH32_MAX_DATA_LEN) return 1;

  size_t hrp_len = strlen(hrp);
  if (hrp_len == 0 || hrp_len > BECH32_MAX_HRP_LEN) return 1;

  for (size_t i = 0; i < hrp_len; i++) {
    char c = hrp[i];
    if (c < 33 || c > 126 || isupper(c)) return 1;
    output[i] = (char)tolower(c);
  }
  output[hrp_len] = '1';

  for (size_t i = 0; i < data_len; i++) {
    if (data[i] >= 32) return 1;
    output[hrp_len + 1 + i] = charset[data[i]];
  }

  uint8_t checksum[6];
  create_checksum(hrp, data, data_len, checksum);
  for (size_t i = 0; i < 6; i++) output[hrp_len + 1 + data_len + i] = charset[checksum[i]];

  output[hrp_len + 1 + data_len + 6] = '\0';
  return 0;
}

int bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input) {
  size_t len = strlen(input);
  if (len < 8 || len > BECH32_MAX_STRING_LEN) return 1;

  size_t pos = 0;
  while (pos < len && input[pos] != '1') pos++;
  if (pos == 0 || pos + 7 > len || pos > BECH32_MAX_HRP_LEN) return 1;

  for (size_t i = 0; i < pos; i++) {
    char c = input[i];
    if (c < 33 || c > 126 || isupper(c)) return 1;
    hrp[i] = (char)tolower(c);
  }
  hrp[pos] = '\0';

  size_t dp_len = len - pos - 1;
  if (dp_len < 6 || dp_len > BECH32_MAX_DATA_LEN + 6 || *data_len < dp_len - 6) return 1;

  for (size_t i = 0; i < dp_len; i++) {
    int8_t v = charset_lut[(uint8_t)input[pos + 1 + i]];
    if (v == -1) return 1;
    data[i] = (uint8_t)v;
  }

  uint8_t buf[BECH32_MAX_HRP_LEN * 2 + 1 + BECH32_MAX_DATA_LEN + 6];
  hrp_expand(hrp, buf);
  size_t prefix_len = pos * 2 + 1;
  memcpy(buf + prefix_len, data, dp_len);
  if (polymod(buf, prefix_len + dp_len) != 1) return 1;

  *data_len = dp_len - 6;
  memmove(data, data, *data_len);

  return 0;
}

int convert_bits(uint8_t *out, size_t *out_len, int to_bits, int from_bits, const uint8_t *in, size_t in_len, int pad) {
  uint32_t acc = 0;
  int bits = 0;
  size_t outpos = 0;
  uint32_t maxv = (uint32_t)((1 << to_bits) - 1);
  uint32_t max_acc = (uint32_t)((1 << (from_bits + to_bits - 1)) - 1);

  for (size_t i = 0; i < in_len; i++) {
    uint8_t value = in[i];
    if (value >> from_bits) return 1;
    acc = ((acc << from_bits) | value) & max_acc;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      if (outpos >= *out_len) return 1;
      out[outpos++] = (uint8_t)((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits) {
      if (outpos >= *out_len) return 1;
      out[outpos++] = (uint8_t)((acc << (to_bits - bits)) & maxv);
    }
  } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv))
    return 1;

  *out_len = outpos;

  return 0;
}
