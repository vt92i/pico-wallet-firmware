#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bip/bip32.h"

#define BIP84_ADDRESS_SIZE     (43)  // 42 characters + 1 for null terminator
#define BIP84_PUBLIC_KEY_SIZE  (33)
#define BIP84_PRIVATE_KEY_SIZE (32)

typedef enum {
  BIP84_STATUS_OK = 0,
  BIP84_STATUS_ERR_BASE58,
  BIP84_STATUS_ERR_UECC,
  BIP84_STATUS_ERR_WITPROG,
  BIP84_STATUS_ERR_SEGWIT_ENCODE,
  BIP84_STATUS_ERR_ADDRESS_ENCODE,
} bip84_status_t;

bip84_status_t bip84_get_index_info(const char root_key[static BIP32_ROOT_KEY_SIZE], const uint32_t index,
                                    char address_out[static BIP84_ADDRESS_SIZE],
                                    uint8_t public_key_out[static BIP84_PUBLIC_KEY_SIZE],
                                    uint8_t private_key_out[static BIP84_PRIVATE_KEY_SIZE]);
