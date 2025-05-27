#pragma once

#include <stddef.h>
#include <stdint.h>

int b58_encode(const uint8_t *input, size_t input_len, char *output, size_t output_len);
int b58_decode(const char *input, uint8_t *output, size_t output_len);
