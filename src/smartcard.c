#include <stdint.h>
#include <stdio.h>

#include "bip39.h"
#include "mbedtls/platform_util.h"
#include "pico/rand.h"

static void generate_entropy(uint8_t entropy_out[BIP39_ENTROPY_SIZE]) {
  rng_128_t rng1, rng2;

  get_rand_128(&rng1);
  get_rand_128(&rng2);

  for (uint8_t i = 0; i < 2; ++i) {
    for (uint8_t j = 0; j < 8; ++j) {
      entropy_out[i * 8 + j] = (rng1.r[i] >> (56 - j * 8)) & 0xFF;
      entropy_out[16 + i * 8 + j] = (rng2.r[i] >> (56 - j * 8)) & 0xFF;
    }
  }

  mbedtls_platform_zeroize((void*)&rng1, sizeof(rng1));
  mbedtls_platform_zeroize((void*)&rng2, sizeof(rng2));
}

void generate_mnemonic() {
  uint8_t entropy[BIP39_ENTROPY_SIZE];
  char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};
  uint8_t seed[BIP39_SEED_SIZE] = {0};

  generate_entropy(entropy);

  char error_buf[128] = {0};
  int ret = 0;

  ret = bip39_generate_mnemonic(entropy, mnemonic, error_buf, sizeof(error_buf));
  if (ret != 0) {
    printf("Error generating mnemonic: %s\n", error_buf);
    return;
  }

  ret = bip39_generate_seed((const char**)mnemonic, seed, error_buf, sizeof(error_buf));
  if (ret != 0) {
    printf("Error generating seed: %s\n", error_buf);
    return;
  }

  mbedtls_platform_zeroize(entropy, sizeof(entropy));
  mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
  mbedtls_platform_zeroize(seed, sizeof(seed));
}
