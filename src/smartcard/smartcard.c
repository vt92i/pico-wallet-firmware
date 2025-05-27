#include "smartcard.h"

#include <stdint.h>
#include <sys/types.h>

#include "hardware/xip_cache.h"
#include "pico/rand.h"

#include "mbedtls/platform_util.h"

#include "bip/bip39.h"
#include "tasks/flash/flash_writer_task.h"
#include "utils/flash.h"

static void generate_entropy(uint8_t entropy[static BIP39_ENTROPY_SIZE]) {
  rng_128_t rng1, rng2;

  get_rand_128(&rng1);
  get_rand_128(&rng2);

  for (uint8_t i = 0; i < 2; ++i) {
    for (uint8_t j = 0; j < 8; ++j) {
      entropy[i * 8 + j] = (rng1.r[i] >> (56 - j * 8)) & 0xFF;
      entropy[16 + i * 8 + j] = (rng2.r[i] >> (56 - j * 8)) & 0xFF;
    }
  }

  mbedtls_platform_zeroize((void*)&rng1, sizeof(rng1));
  mbedtls_platform_zeroize((void*)&rng2, sizeof(rng2));
}

static bool generate_mnemonic(char* mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  uint8_t entropy[BIP39_ENTROPY_SIZE];
  generate_entropy(entropy);

  bip39_status_t status = bip39_generate_mnemonic(entropy, mnemonic);
  if (status != BIP39_STATUS_OK) return false;

  mbedtls_platform_zeroize(entropy, sizeof(entropy));
  return true;
}

static bool generate_seed(const char* mnemonic[static BIP39_MNEMONIC_LENGTH], uint8_t seed[static BIP39_SEED_SIZE]) {
  bip39_status_t ret = bip39_generate_seed(mnemonic, seed);
  if (ret != 0) return false;

  return true;
}

smartcard_status_t smartcard_get_wallet_status(void) {
  xip_cache_clean_all();

  if (flash_target_contents[0] != 0x01) return SMARTCARD_STATUS_ERROR;
  return SMARTCARD_STATUS_OK;
}

smartcard_status_t smartcard_initialize_wallet(char* mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) return SMARTCARD_STATUS_ERROR;

  uint8_t seed[BIP39_SEED_SIZE] = {0};

  if (!generate_mnemonic(mnemonic)) return SMARTCARD_STATUS_ERROR;
  if (!generate_seed((const char**)mnemonic, seed)) {
    mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
    return SMARTCARD_STATUS_ERROR;
  }

  flash_buffer_t flash_buffer = {
      .data = seed,
      .data_len = BIP39_SEED_SIZE,
  };
  xQueueOverwrite(flash_rx_queue, &flash_buffer);

  return SMARTCARD_STATUS_OK;
}
