#pragma once

#include <stddef.h>
#include <stdint.h>

int segwit_address_encode(char *output, size_t output_len, const char *hrp, int witver, const uint8_t *witprog,
                          size_t witprog_len);
int segwit_address_decode(char *hrp, const char *addr, int *witver, uint8_t *witprog, size_t *witprog_len);
