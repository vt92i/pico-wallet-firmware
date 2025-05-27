#pragma once

#include "rpc/rpc.h"

bool handle_initialize_wallet(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_reset_wallet(const rpc_payload_t* payload, rpc_buffer_t* response);
