#ifndef _BIP32_H_
#define _BIP32_H_

#include <stdint.h>

#include "bip39.h"

#define BIP32_ROOT_KEY_SIZE (111 + 1)  // 111 bytes + 1 for null terminator

typedef enum {
  BIP32_STATUS_OK = 0,
  BIP32_STATUS_ERR_NULL_INPUT,
  BIP32_STATUS_ERR_SHA256,
  BIP32_STATUS_ERR_HMAC,
} bip32_status_t;

bip32_status_t bip32_generate_root_key(const uint8_t seed[BIP39_SEED_SIZE], uint8_t root_key[BIP32_ROOT_KEY_SIZE]);

#endif /* _BIP32_H_ */
