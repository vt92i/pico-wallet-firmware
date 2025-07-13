#include "base58.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline size_t b58_encoded_max_size(size_t input_len) { return (input_len * 138) / 100 + 2; }
static const char *B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int b58_encode(const uint8_t *input, size_t input_len, char *output, size_t output_len) {
  uint8_t buffer[b58_encoded_max_size(input_len)];
  memset(buffer, 0, sizeof(buffer));

  size_t zero_count = 0;
  while (zero_count < input_len && input[zero_count] == 0) zero_count++;

  size_t size = 0;
  for (size_t i = zero_count; i < input_len; i++) {
    int carry = input[i];
    size_t j = 0;
    for (; j < size || carry; j++) {
      carry += 256 * buffer[j];
      buffer[j] = (uint8_t)(carry % 58);
      carry /= 58;
    }
    size = j;
  }

  size_t full_size = zero_count + size;
  if (output_len < full_size + 1) return 1;  // +1 for null terminator

  size_t index = 0;
  for (; index < zero_count; index++) output[index] = '1';

  for (size_t i = 0; i < size; i++) output[index + i] = B58_ALPHABET[buffer[size - 1 - i]];
  output[full_size] = '\0';

  return 0;
}

int b58_decode(const char *input, uint8_t *output, size_t output_len) {
  size_t input_len = strlen(input);

  uint8_t buffer[output_len];
  memset(buffer, 0, output_len);

  size_t zero_count = 0;
  while (zero_count < input_len && input[zero_count] == '1') zero_count++;

  size_t size = 0;
  for (size_t i = zero_count; i < input_len; i++) {
    const char *p = strchr(B58_ALPHABET, input[i]);
    if (!p) return 1;

    int carry = (int)(p - B58_ALPHABET);
    size_t j = 0;
    for (; j < size || carry; j++) {
      if (j >= output_len) return 1;

      carry += 58 * buffer[j];
      buffer[j] = (uint8_t)(carry & 0xFF);
      carry >>= 8;
    }
    size = j;
  }

  size_t full_size = zero_count + size;
  if (full_size > output_len) return 1;

  size_t index = 0;
  for (; index < zero_count; index++) output[index] = 0;

  for (size_t i = 0; i < size; i++) output[index + i] = buffer[size - 1 - i];

  return 0;
}
