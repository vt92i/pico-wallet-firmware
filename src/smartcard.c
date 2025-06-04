#include "smartcard.h"

#include <stdint.h>
#include <stdio.h>

#include "bip39.h"
#include "flash.h"
#include "hardware/xip_cache.h"
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

bool generate_mnemonic(char* mnemonic_out[BIP39_MNEMONIC_LENGTH]) {
  uint8_t entropy[BIP39_ENTROPY_SIZE];
  generate_entropy(entropy);

  printf("Entropy: \n");
  for (uint8_t i = 0; i < BIP39_ENTROPY_SIZE; i++) {
    printf("%02x", entropy[i]);
  }
  printf("\n");

  bip39_status_t status = bip39_generate_mnemonic(entropy, mnemonic_out);
  if (status != BIP39_STATUS_OK) return false;

  mbedtls_platform_zeroize(entropy, sizeof(entropy));
  return true;
}

bool generate_seed(const char mnemonic[BIP39_MNEMONIC_LENGTH], uint8_t seed_out[BIP39_SEED_SIZE]) {
  bip39_status_t ret = bip39_generate_seed((const char**)mnemonic, seed_out);
  if (ret != 0) return false;

  return true;
}

smartcard_status_t smartcard_get_wallet_status() {
  xip_cache_clean_all();

  printf("Seed: \n");
  for (uint8_t i = 1; i < BIP39_SEED_SIZE + 1; i++) {
    printf("%02x", flash_target_contents[i]);
  }
  printf("\n");

  if (flash_target_contents[0] != 0x01) return SMARTCARD_STATUS_ERROR;
  return SMARTCARD_STATUS_OK;
}
