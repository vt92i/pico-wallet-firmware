#pragma once

#include "rpc/rpc.h"

bool handle_initialize_wallet(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_reset_wallet(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_get_wallet_status(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_get_address(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_get_public_key(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_sign_transaction(const rpc_payload_t* payload, rpc_buffer_t* response);
