#pragma once

#include <stdint.h>

#include "bip/bip39.h"

typedef enum {
  SMARTCARD_STATUS_OK = 0x00,
  SMARTCARD_STATUS_ERROR = 0xFF,
} smartcard_status_t;

typedef struct {
  uint8_t* data;
  uint8_t data_len;
  smartcard_status_t status;
} smartcard_response_t;

smartcard_status_t smartcard_get_wallet_status(void);
smartcard_status_t smartcard_initialize_wallet(char* mnemonic[static BIP39_MNEMONIC_LENGTH]);
