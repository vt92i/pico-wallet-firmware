#pragma once

#include "rpc.h"
#include "rpc/commands/command_hash.h"
#include "rpc/commands/command_wallet.h"
#include "rpc/commands/rpc_commands.h"

typedef bool (*rpc_command_fn)(const rpc_payload_t*, rpc_buffer_t*);

typedef struct {
  uint8_t cmd;
  rpc_command_fn handler;
} rpc_command_handler_t;

static const rpc_command_handler_t command_handlers[] = {
    {RPC_COMMAND_HASH_MD5, handle_md5},
    {RPC_COMMAND_HASH_SHA256, handle_sha256},

    {RPC_COMMAND_INITIALIZE_WALLET, handle_initialize_wallet},
    {RPC_COMMAND_RESET_WALLET, handle_reset_wallet},
};

#define NUM_COMMAND_HANDLERS (sizeof(command_handlers) / sizeof(command_handlers[0]))

rpc_buffer_t rpc_handle(const rpc_buffer_t* buffer);
