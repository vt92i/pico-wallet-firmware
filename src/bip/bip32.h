#pragma once

#include <stdint.h>

#include "bip39.h"

#define BIP32_ROOT_KEY_SIZE (112)  // 111 characters + 1 for null terminator

typedef enum {
  BIP32_STATUS_OK = 0,
  BIP32_STATUS_ERR_MD_INFO,
  BIP32_STATUS_ERR_BASE58,
  BIP32_STATUS_ERR_SHA256,
  BIP32_STATUS_ERR_HMAC,
} bip32_status_t;

bip32_status_t bip32_generate_root_key(const uint8_t seed[static BIP39_SEED_SIZE],
                                       char root_key[static BIP32_ROOT_KEY_SIZE]);
