#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bip/bip39.h"

typedef enum {
  SMARTCARD_INITIALIZE_WALLET = 0x00,
  SMARTCARD_RESET_WALLET = 0xFF,

  SMARTCARD_GET_WALLET_STATUS = 0x02,
  SMARTCARD_GET_ADDRESS = 0x03,
  SMARTCARD_GET_PUBLIC_KEY = 0x04,

  SMARTCARD_SIGN_TRANSACTION = 0x05,
} smartcard_command_t;

typedef enum {
  SMARTCARD_STATUS_OK = 0x00,
  SMARTCARD_STATUS_PROCESSING = 0x01,
  SMARTCARD_STATUS_ERROR = 0xFF,
} smartcard_status_t;

typedef struct {
  uint8_t data, data_len;
  smartcard_status_t status;
} smartcard_response_t;

static void generate_entropy(uint8_t entropy_out[BIP39_ENTROPY_SIZE]);

bool generate_mnemonic(char* mnemonic_out[BIP39_MNEMONIC_LENGTH]);
bool generate_seed(const char* mnemonic, uint8_t seed_out[BIP39_SEED_SIZE]);

smartcard_status_t smartcard_get_wallet_status();
