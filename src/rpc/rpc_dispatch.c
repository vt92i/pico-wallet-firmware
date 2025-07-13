#include "rpc_dispatch.h"

#include <stddef.h>
#include <stdio.h>

#include "rpc.h"
#include "rpc_utils.h"

rpc_buffer_t rpc_handle(const rpc_buffer_t* buffer) {
  uint8_t tx_buffer_data[RPC_MAX_TX_PACKET_SIZE] = {0};
  rpc_buffer_t tx_buffer = {
      .data = tx_buffer_data,
      .data_len = 0,
  };

  rpc_command_t command = buffer->data[RPC_HEADER_SIZE];
  rpc_payload_t payload = {
      .data = buffer->data + RPC_HEADER_SIZE + RPC_CMD_SIZE,
      .data_len = buffer->data_len,
  };

  for (size_t i = 0; i < NUM_COMMAND_HANDLERS; i++) {
    if (command_handlers[i].cmd == command)
      if (command_handlers[i].handler(&payload, &tx_buffer)) return tx_buffer;
  }

  rpc_build_response(&tx_buffer, RPC_STATUS_INVALID_COMMAND, NULL, 0);
  return tx_buffer;
}
