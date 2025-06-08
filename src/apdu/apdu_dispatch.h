#pragma once

#include "apdu.h"
#include "apdu/commands/apdu_commands.h"
#include "apdu/commands/command_hash.h"
#include "apdu/commands/command_wallet.h"

typedef bool (*apdu_command_fn)(const apdu_packet_t*, apdu_buffer_t*);

typedef struct {
  uint8_t ins;
  apdu_command_fn handler;
} apdu_command_handler_t;

static const apdu_command_handler_t command_handlers[] = {
    {APDU_INS_HASH_MD5, handle_md5},
    {APDU_INS_HASH_SHA256, handle_sha256},
    {APDU_INS_INITIALIZE_WALLET, handle_initialize_wallet},
    {APDU_INS_RESET_WALLET, handle_reset_wallet},
};

#define NUM_COMMAND_HANDLERS (sizeof(command_handlers) / sizeof(command_handlers[0]))

apdu_buffer_t apdu_handle(const apdu_buffer_t* apdu_buffer);
