#include "smartcard.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hardware/xip_cache.h"
#include "pico/rand.h"

#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#include "bip/bip39.h"
#include "bip/bip84.h"
#include "tasks/flash/flash_writer_task.h"
#include "uECC.h"
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

  mbedtls_platform_zeroize((void *)&rng1, sizeof(rng1));
  mbedtls_platform_zeroize((void *)&rng2, sizeof(rng2));
}

static bool generate_mnemonic(char *mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  uint8_t entropy[BIP39_ENTROPY_SIZE];
  generate_entropy(entropy);

  bip39_status_t status = bip39_generate_mnemonic(entropy, mnemonic);
  if (status != BIP39_STATUS_OK) return false;

  mbedtls_platform_zeroize(entropy, sizeof(entropy));
  return true;
}

static bool generate_seed(const char *mnemonic[static BIP39_MNEMONIC_LENGTH], uint8_t seed[static BIP39_SEED_SIZE]) {
  bip39_status_t ret = bip39_generate_seed(mnemonic, seed);
  if (ret != 0) return false;

  return true;
}

smartcard_status_t smartcard_initialize_wallet(char *mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) return SMARTCARD_STATUS_ERROR;

  uint8_t seed[BIP39_SEED_SIZE] = {0};

  if (!generate_mnemonic(mnemonic)) return SMARTCARD_STATUS_ERROR;
  if (!generate_seed((const char **)mnemonic, seed)) {
    mbedtls_platform_zeroize(mnemonic, sizeof(char *) * BIP39_MNEMONIC_LENGTH);
    return SMARTCARD_STATUS_ERROR;
  }

  flash_buffer_t flash_buffer = {
      .data = NULL,
      .data_len = sizeof(seed),
  };

  flash_buffer.data = pvPortMalloc(flash_buffer.data_len);
  if (flash_buffer.data == NULL) {
    mbedtls_platform_zeroize(mnemonic, sizeof(char *) * BIP39_MNEMONIC_LENGTH);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return SMARTCARD_STATUS_ERROR;
  }

  memcpy(flash_buffer.data, seed, flash_buffer.data_len);
  xQueueOverwrite(flash_rx_queue, &flash_buffer);
  mbedtls_platform_zeroize(seed, sizeof(seed));
  // vPortFree(flash_buffer.data);  // Don't free here, as the flash writer task will handle it

  return SMARTCARD_STATUS_OK;
}

smartcard_status_t smartcard_get_wallet_status(void) {
  xip_cache_clean_all();

  if (flash_target_contents[0] != 0x01) return SMARTCARD_STATUS_ERROR;
  return SMARTCARD_STATUS_OK;
}

smartcard_status_t smartcard_get_address(const uint8_t index, char address[static BIP84_ADDRESS_SIZE]) {
  if (smartcard_get_wallet_status() != SMARTCARD_STATUS_OK) return SMARTCARD_STATUS_ERROR;

  uint8_t seed[BIP39_SEED_SIZE] = {0};
  for (size_t i = 0; i < BIP39_SEED_SIZE; i++) seed[i] = flash_target_contents[i + 1];

  char root_key[BIP32_ROOT_KEY_SIZE] = {0};
  bip32_status_t bip32_status = bip32_generate_root_key(seed, root_key);
  if (bip32_status != BIP32_STATUS_OK) {
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(seed, sizeof(seed));

  uint8_t public_key[BIP84_PUBLIC_KEY_SIZE] = {0};
  uint8_t private_key[BIP84_PRIVATE_KEY_SIZE] = {0};

  bip84_status_t bip84_status = bip84_get_index_info((const char *)root_key, index, address, public_key, private_key);
  if (bip84_status != BIP84_STATUS_OK) {
    mbedtls_platform_zeroize(root_key, sizeof(root_key));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(root_key, sizeof(root_key));
  mbedtls_platform_zeroize(public_key, sizeof(public_key));
  mbedtls_platform_zeroize(private_key, sizeof(private_key));

  return SMARTCARD_STATUS_OK;
}

smartcard_status_t smartcard_get_public_key(const uint8_t index, uint8_t public_key[static BIP84_PUBLIC_KEY_SIZE]) {
  if (smartcard_get_wallet_status() != SMARTCARD_STATUS_OK) return SMARTCARD_STATUS_ERROR;

  uint8_t seed[BIP39_SEED_SIZE] = {0};
  for (size_t i = 0; i < BIP39_SEED_SIZE; i++) seed[i] = flash_target_contents[i + 1];

  char root_key[BIP32_ROOT_KEY_SIZE] = {0};
  bip32_status_t bip32_status = bip32_generate_root_key(seed, root_key);
  if (bip32_status != BIP32_STATUS_OK) {
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(seed, sizeof(seed));

  char address[BIP84_ADDRESS_SIZE] = {0};
  uint8_t private_key[BIP84_PRIVATE_KEY_SIZE] = {0};

  bip84_status_t bip84_status = bip84_get_index_info((const char *)root_key, index, address, public_key, private_key);
  if (bip84_status != BIP84_STATUS_OK) {
    mbedtls_platform_zeroize(root_key, sizeof(root_key));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(root_key, sizeof(root_key));
  mbedtls_platform_zeroize(address, sizeof(address));
  mbedtls_platform_zeroize(private_key, sizeof(private_key));

  return SMARTCARD_STATUS_OK;
}

smartcard_status_t smartcard_get_private_key(const uint8_t index, uint8_t private_key[static BIP84_PRIVATE_KEY_SIZE]) {
  if (smartcard_get_wallet_status() != SMARTCARD_STATUS_OK) return SMARTCARD_STATUS_ERROR;

  uint8_t seed[BIP39_SEED_SIZE] = {0};
  for (size_t i = 0; i < BIP39_SEED_SIZE; i++) seed[i] = flash_target_contents[i + 1];

  char root_key[BIP32_ROOT_KEY_SIZE] = {0};
  bip32_status_t bip32_status = bip32_generate_root_key(seed, root_key);
  if (bip32_status != BIP32_STATUS_OK) {
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(seed, sizeof(seed));

  char address[BIP84_ADDRESS_SIZE] = {0};
  uint8_t public_key[BIP84_PUBLIC_KEY_SIZE] = {0};

  bip84_status_t bip84_status = bip84_get_index_info((const char *)root_key, index, address, public_key, private_key);
  if (bip84_status != BIP84_STATUS_OK) {
    mbedtls_platform_zeroize(root_key, sizeof(root_key));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(root_key, sizeof(root_key));
  mbedtls_platform_zeroize(address, sizeof(address));
  mbedtls_platform_zeroize(public_key, sizeof(public_key));

  return SMARTCARD_STATUS_OK;
}

static mbedtls_sha256_context sha_ctx;
static void mbedtls_init_hash(const struct uECC_HashContext *context) {
  (void)context;
  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts_ret(&sha_ctx, 0);
}

static void mbedtls_update_hash(const struct uECC_HashContext *context, const uint8_t *message, unsigned message_size) {
  (void)context;
  mbedtls_sha256_update_ret(&sha_ctx, message, message_size);
}

static void mbedtls_finish_hash(const struct uECC_HashContext *context, uint8_t *hash_result) {
  (void)context;
  mbedtls_sha256_finish_ret(&sha_ctx, hash_result);
  mbedtls_sha256_free(&sha_ctx);
}

static const uint8_t SECP256K1_N[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
                                      0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
                                      0x41, 0x41, 0x02, 0xDF, 0x32, 0xC5, 0x1D, 0xB7, 0x2E, 0xC7};

static void enforce_low_s(uint8_t *signature) {
  uint8_t s[32];
  memcpy(s, signature + 32, 32);

  uint8_t half_n[32];
  memcpy(half_n, SECP256K1_N, 32);
  for (int i = 31; i >= 0; i--) {
    uint16_t val = half_n[i];
    half_n[i] = (uint8_t)(val >> 1);
    if (i > 0 && (half_n[i - 1] & 1)) {
      half_n[i] |= 0x80;
    }
  }

  if (memcmp(s, half_n, 32) > 0) {
    uint8_t new_s[32];
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
      uint16_t diff = (uint16_t)(SECP256K1_N[i] - s[i] - carry);
      carry = (s[i] + carry > SECP256K1_N[i]) ? 1 : 0;
      new_s[i] = (uint8_t)(diff & 0xFF);
    }
    memcpy(signature + 32, new_s, 32);
  }
}

static size_t der_encode_integer(const uint8_t *value, uint8_t *out) {
  size_t i = 0;
  while (i < 32 && value[i] == 0) i++;

  size_t len = 32 - i;
  int needs_padding = (value[i] & 0x80) ? 1 : 0;

  size_t offset = 0;
  out[offset++] = 0x02;
  out[offset++] = (uint8_t)((size_t)len + (size_t)needs_padding);

  if (needs_padding) out[offset++] = 0x00;
  memcpy(out + offset, value + i, len);
  offset += len;

  return offset;
}

static size_t uECC_signature_to_der(const uint8_t signature[64], uint8_t *der_out) {
  uint8_t r_der[40];
  uint8_t s_der[40];

  size_t r_len = der_encode_integer(signature, r_der);
  size_t s_len = der_encode_integer(signature + 32, s_der);

  size_t total_len = r_len + s_len;
  der_out[0] = 0x30;
  der_out[1] = (uint8_t)total_len;
  memcpy(der_out + 2, r_der, r_len);
  memcpy(der_out + 2 + r_len, s_der, s_len);

  return 2 + total_len;
}

smartcard_status_t smartcard_sign_transaction(const uint8_t index, const uint8_t *preimage_hash,
                                              uint8_t *sig_plus_sighash_out, size_t *sig_len_out) {
  uint8_t private_key[BIP84_PRIVATE_KEY_SIZE] = {0};
  smartcard_status_t status = smartcard_get_private_key(index, private_key);
  if (status != SMARTCARD_STATUS_OK) return status;

  const uint8_t block_size = 64;
  const uint8_t result_size = 32;
  uint8_t tmp_buffer[2 * block_size + result_size];

  uECC_HashContext hash_ctx = {.init_hash = mbedtls_init_hash,
                               .update_hash = mbedtls_update_hash,
                               .finish_hash = mbedtls_finish_hash,
                               .block_size = block_size,
                               .result_size = result_size,
                               .tmp = tmp_buffer};

  uint8_t raw_signature[64] = {0};
  int ret = uECC_sign_deterministic(private_key, preimage_hash, 32, &hash_ctx, raw_signature, uECC_secp256k1());
  if (ret != 1) {
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    mbedtls_platform_zeroize(raw_signature, sizeof(raw_signature));
    return SMARTCARD_STATUS_ERROR;
  }

  mbedtls_platform_zeroize(private_key, sizeof(private_key));

  enforce_low_s(raw_signature);
  size_t der_len = uECC_signature_to_der(raw_signature, sig_plus_sighash_out);

  sig_plus_sighash_out[der_len] = 0x01;
  *sig_len_out = der_len + 1;

  return SMARTCARD_STATUS_OK;
}
