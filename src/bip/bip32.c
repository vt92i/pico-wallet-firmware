#include "bip32.h"

#include <stdint.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "bip39.h"
#include "utils/base58.h"

bip32_status_t bip32_generate_root_key(const uint8_t seed[static BIP39_SEED_SIZE],
                                       char root_key[static BIP32_ROOT_KEY_SIZE]) {
  const uint8_t xprv_version[4] = {0x04, 0x35, 0x83, 0x94};  // Testnet version
  const uint8_t xprv_depth[1] = {0x00};
  const uint8_t xprv_fingerprint[4] = {0x00, 0x00, 0x00, 0x00};
  const uint8_t xprv_child_number[4] = {0x00, 0x00, 0x00, 0x00};

  uint8_t xprv_chain_code[32] = {0};
  uint8_t xprv_private_key[33] = {0};

  const uint8_t *key = (const uint8_t *)"Bitcoin seed";

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (md_info == NULL) {
    mbedtls_platform_zeroize(root_key, BIP32_ROOT_KEY_SIZE);
    return BIP32_STATUS_ERR_MD_INFO;
  }

  int ret;

  uint8_t hmac_sha512_digest[64] = {0};
  ret = mbedtls_md_hmac(md_info, key, strlen((const char *)key), seed, BIP39_SEED_SIZE, hmac_sha512_digest);
  if (ret != 0) {
    mbedtls_platform_zeroize(root_key, BIP32_ROOT_KEY_SIZE);
    mbedtls_platform_zeroize(hmac_sha512_digest, sizeof(hmac_sha512_digest));
    return BIP32_STATUS_ERR_HMAC;
  }

  memcpy(xprv_chain_code, hmac_sha512_digest + 32, 32);
  memcpy(xprv_private_key + 1, hmac_sha512_digest, 32);

  memcpy(root_key, xprv_version, sizeof(xprv_version));
  memcpy(root_key + sizeof(xprv_version), xprv_depth, sizeof(xprv_depth));
  memcpy(root_key + sizeof(xprv_version) + sizeof(xprv_depth), xprv_fingerprint, sizeof(xprv_fingerprint));
  memcpy(root_key + sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint), xprv_child_number,
         sizeof(xprv_child_number));
  memcpy(root_key + sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint) + sizeof(xprv_child_number),
         xprv_chain_code, sizeof(xprv_chain_code));
  memcpy(root_key + sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint) + sizeof(xprv_child_number) +
             sizeof(xprv_chain_code),
         xprv_private_key, sizeof(xprv_private_key));

  uint8_t sha256_digest[32] = {0};
  ret = mbedtls_sha256_ret((const uint8_t *)root_key,
                           sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint) +
                               sizeof(xprv_child_number) + sizeof(xprv_chain_code) + sizeof(xprv_private_key),
                           sha256_digest, 0);
  if (ret != 0) {
    mbedtls_platform_zeroize(root_key, BIP32_ROOT_KEY_SIZE);
    mbedtls_platform_zeroize(hmac_sha512_digest, sizeof(hmac_sha512_digest));
    mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
    mbedtls_platform_zeroize(xprv_chain_code, sizeof(xprv_chain_code));
    mbedtls_platform_zeroize(xprv_private_key, sizeof(xprv_private_key));
    return BIP32_STATUS_ERR_SHA256;
  }
  ret = mbedtls_sha256_ret(sha256_digest, sizeof(sha256_digest), sha256_digest, 0);
  if (ret != 0) {
    mbedtls_platform_zeroize(root_key, BIP32_ROOT_KEY_SIZE);
    mbedtls_platform_zeroize(hmac_sha512_digest, sizeof(hmac_sha512_digest));
    mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
    mbedtls_platform_zeroize(xprv_chain_code, sizeof(xprv_chain_code));
    mbedtls_platform_zeroize(xprv_private_key, sizeof(xprv_private_key));
    return BIP32_STATUS_ERR_SHA256;
  }

  memcpy(root_key + sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint) + sizeof(xprv_child_number) +
             sizeof(xprv_chain_code) + sizeof(xprv_private_key),
         sha256_digest, 4);

  mbedtls_platform_zeroize(hmac_sha512_digest, sizeof(hmac_sha512_digest));
  mbedtls_platform_zeroize(sha256_digest, sizeof(sha256_digest));
  mbedtls_platform_zeroize(xprv_chain_code, sizeof(xprv_chain_code));
  mbedtls_platform_zeroize(xprv_private_key, sizeof(xprv_private_key));

  if (b58_encode((const uint8_t *)root_key,
                 sizeof(xprv_version) + sizeof(xprv_depth) + sizeof(xprv_fingerprint) + sizeof(xprv_child_number) +
                     sizeof(xprv_chain_code) + sizeof(xprv_private_key) + 4,
                 root_key, BIP32_ROOT_KEY_SIZE) != 0) {
    mbedtls_platform_zeroize(root_key, BIP32_ROOT_KEY_SIZE);
    return BIP32_STATUS_ERR_BASE58;
  }

  return BIP32_STATUS_OK;
}
