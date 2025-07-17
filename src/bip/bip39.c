#include "bip39.h"

#include <stdint.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

static void bytes_to_bin(const uint8_t* bytes, size_t byte_len, char* bin_out) {
  for (size_t i = 0; i < byte_len; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      *bin_out++ = ((bytes[i] >> bit) & 1) ? '1' : '0';
    }
  }
  *bin_out = '\0';
}

bip39_status_t bip39_generate_mnemonic(const uint8_t entropy[static BIP39_ENTROPY_SIZE],
                                       char* mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  uint8_t sha256_digest[32] = {0};
  int ret = mbedtls_sha256_ret(entropy, BIP39_ENTROPY_SIZE, sha256_digest, 0);
  if (ret != 0) {
    mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
    return BIP39_STATUS_ERR_SHA256;
  }

  char entropy_bin[BIP39_ENTROPY_BITS + 1] = {
      0};  // Binary representation of entropy (8 bits for 1 byte) + 1 for null terminator
  char sha256_bin[BIP39_SHA256_BITS + 1] = {
      0};  // SHA-256 binary representation (8 bits for 1 byte) + 1 for null terminator
  char final_bin[BIP39_FINAL_BIN_SIZE + 1] = {
      0};  // Final binary representation (entropy + SHA-256) + 1 for null terminator

  bytes_to_bin(entropy, BIP39_ENTROPY_SIZE, entropy_bin);  // Convert entropy to binary string
  bytes_to_bin(sha256_digest, 1, sha256_bin);              // Convert only the first byte of SHA-256 to binary string

  memcpy(final_bin, entropy_bin, BIP39_ENTROPY_BITS);
  memcpy(final_bin + BIP39_ENTROPY_BITS, sha256_bin, BIP39_SHA256_BITS);

  mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
  mbedtls_platform_zeroize(entropy_bin, sizeof(entropy_bin));
  mbedtls_platform_zeroize(sha256_bin, sizeof(sha256_bin));

  for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
    size_t idx = 0;
    for (size_t j = 0; j < 11; j++)
      if (final_bin[i * 11 + j] == '1') idx |= (1 << (10 - j));  // Convert binary to index

    if (idx < sizeof(BIP39_WORDS) / sizeof(BIP39_WORDS[0])) mnemonic[i] = (char*)BIP39_WORDS[idx];
  }

  mbedtls_platform_zeroize(final_bin, sizeof(final_bin));
  return BIP39_STATUS_OK;
}

bip39_status_t bip39_check_mnemonic(const char* mnemonic[static BIP39_MNEMONIC_LENGTH]) {
  uint16_t indices[BIP39_MNEMONIC_LENGTH] = {0};
  size_t checksum_bits_len = BIP39_ENTROPY_BITS / 32;
  size_t total_bits = BIP39_ENTROPY_BITS + checksum_bits_len;
  size_t total_bytes = (total_bits + 7) / 8;

  uint8_t data[total_bytes];
  memset(data, 0, sizeof(data));

  for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
    int found = 0;
    for (uint16_t j = 0; j < 2048; j++) {
      if (strcmp(mnemonic[i], BIP39_WORDS[j]) == 0) {
        indices[i] = j;
        found = 1;
        break;
      }
    }
    if (!found) return BIP39_STATUS_ERR_INVALID_WORD;
  }

  size_t bit_offset = 0;
  for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
    uint16_t idx = indices[i];
    for (int b = 10; b >= 0; b--) {
      if ((idx >> b) & 1) data[bit_offset / 8] |= (1 << (7 - (bit_offset % 8)));
      bit_offset++;
    }
  }

  uint8_t* entropy = data;
  uint8_t checksum_input_byte = data[BIP39_ENTROPY_SIZE];
  uint8_t checksum_given = checksum_input_byte >> (8 - checksum_bits_len);

  uint8_t sha256_digest[32] = {0};
  if (mbedtls_sha256_ret(entropy, BIP39_ENTROPY_SIZE, sha256_digest, 0) != 0) {
    mbedtls_platform_zeroize(data, sizeof(data));
    return BIP39_STATUS_ERR_SHA256;
  }

  uint8_t checksum_expected = sha256_digest[0] >> (8 - checksum_bits_len);

  mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
  mbedtls_platform_zeroize(data, sizeof(data));

  if (checksum_expected != checksum_given) return BIP39_STATUS_ERR_INVALID_CHECKSUM;

  return BIP39_STATUS_OK;
}

bip39_status_t bip39_generate_seed(const char* mnemonic[static BIP39_MNEMONIC_LENGTH],
                                   uint8_t seed[static BIP39_SEED_SIZE]) {
  uint8_t m[BIP39_MNEMONIC_LENGTH * BIP39_MAX_WORD_SIZE + 1] = {0};

  size_t offset = 0;
  for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
    if (mnemonic[i] == NULL) return BIP39_STATUS_ERR_INVALID_WORD;

    size_t word_len = strnlen(mnemonic[i], BIP39_MAX_WORD_SIZE);
    if (offset + word_len + 1 >= sizeof(m)) break;  // +1 for space or null terminator

    memcpy(m + offset, mnemonic[i], word_len);
    offset += word_len;

    if (i < BIP39_MNEMONIC_LENGTH - 1) m[offset++] = ' ';
  }
  m[offset] = '\0';  // Ensure null termination

  const uint8_t* passphrase = (const uint8_t*)"mnemonic";  // TODO: Add passphrase support

  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* md_info;

  mbedtls_md_init(&ctx);
  md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  int ret = mbedtls_md_setup(&ctx, md_info, 1);

  if (ret != 0) {
    mbedtls_md_free(&ctx);
    mbedtls_platform_zeroize(seed, BIP39_SEED_SIZE);
    return BIP39_STATUS_ERR_SHA256;
  }

  ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const uint8_t*)m, strlen((const char*)m), passphrase,
                                  strlen((const char*)passphrase), PBKDF2_ROUNDS, BIP39_SEED_SIZE, seed);

  mbedtls_platform_zeroize(m, sizeof(m));
  mbedtls_md_free(&ctx);

  if (ret != 0) {
    mbedtls_platform_zeroize(seed, BIP39_SEED_SIZE);
    return BIP39_STATUS_ERR_PBKDF2;
  }

  return BIP39_STATUS_OK;
}
