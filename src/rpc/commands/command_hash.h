#pragma once

#include "rpc/rpc.h"

bool handle_md5(const rpc_payload_t* payload, rpc_buffer_t* response);
bool handle_sha256(const rpc_payload_t* payload, rpc_buffer_t* response);
