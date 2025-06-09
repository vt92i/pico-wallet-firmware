#include <stdio.h>

#include "bech32.h"

int segwit_address_encode(char *output, size_t output_len, const char *hrp, int witver, const uint8_t *witprog,
                          size_t witprog_len) {
  (void)output_len;

  uint8_t data[1 + 65];
  size_t datalen = sizeof(data);

  if (witver < 0 || witver > 16 || witprog_len < 2 || witprog_len > 40) return 1;

  data[0] = (uint8_t)witver;
  if (convert_bits(data + 1, &datalen, 5, 8, witprog, witprog_len, 1) != 0) return 1;
  datalen += 1;

  return bech32_encode(hrp, data, datalen, output);
}

int segwit_address_decode(char *hrp, const char *addr, int *witver, uint8_t *witprog, size_t *witprog_len) {
  uint8_t data[90];
  size_t datalen = sizeof(data);

  if (!bech32_decode(hrp, data, &datalen, addr)) return 1;

  if (datalen < 1 || datalen > 65) return 1;
  if (data[0] > 16) return 1;

  *witver = data[0];

  size_t prog_len = *witprog_len;
  if (!convert_bits(witprog, &prog_len, 8, 5, data + 1, datalen - 1, 0)) return 1;

  if (prog_len < 2 || prog_len > 40) return 1;
  *witprog_len = prog_len;

  return 0;
}
