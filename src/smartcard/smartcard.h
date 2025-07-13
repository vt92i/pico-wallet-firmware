#pragma once

#include <stdint.h>

#include "bip/bip39.h"
#include "bip/bip84.h"
#include "commands/smartcard_commands.h"

typedef enum {
  SMARTCARD_STATUS_OK = 0x00,
  SMARTCARD_STATUS_ERROR = 0xFF,
} smartcard_status_t;

typedef struct {
  smartcard_command_t command;
  uint8_t* data;
  uint16_t data_len;
} smartcard_request_t;

typedef struct {
  uint8_t* data;
  uint16_t data_len;
  smartcard_status_t status;
} smartcard_response_t;

smartcard_status_t smartcard_initialize_wallet(char* mnemonic[static BIP39_MNEMONIC_LENGTH]);
smartcard_status_t smartcard_get_wallet_status(void);
smartcard_status_t smartcard_get_address(const uint8_t index, char address[static BIP84_ADDRESS_SIZE]);
smartcard_status_t smartcard_get_public_key(const uint8_t index, uint8_t public_key[static BIP84_PUBLIC_KEY_SIZE]);
smartcard_status_t smartcard_get_private_key(const uint8_t index, uint8_t private_key[static BIP84_PRIVATE_KEY_SIZE]);
smartcard_status_t smartcard_sign_transaction(const uint8_t index, const uint8_t* preimage_hash,
                                              uint8_t* sig_plus_sighash_out, size_t* sig_len_out);
