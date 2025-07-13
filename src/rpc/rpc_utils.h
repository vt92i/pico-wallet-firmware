#pragma once

#include "rpc.h"

void rpc_build_response(rpc_buffer_t* buffer, const rpc_status_t status, const uint8_t* data, const uint16_t data_len);
