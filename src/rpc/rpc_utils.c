#include "rpc_utils.h"

#include <stdint.h>
#include <string.h>

#include "rpc.h"

void rpc_build_response(rpc_buffer_t* buffer, const rpc_status_t status, const uint8_t* data, const uint16_t data_len) {
  if (buffer == NULL) return;

  if (data_len <= RPC_MAX_DATA_LEN && data != NULL) {
    buffer->data[0] = (uint8_t)((data_len >> 8) & 0xFF);
    buffer->data[1] = (uint8_t)(data_len & 0xFF);

    memcpy(buffer->data + RPC_HEADER_SIZE + RPC_STATUS_SIZE, data, data_len);
  }

  buffer->data[RPC_STATUS_SIZE] = (uint8_t)((status >> 8) & 0xFF);
  buffer->data[RPC_STATUS_SIZE + 1] = (uint8_t)(status & 0xFF);

  buffer->data_len = data_len;
}
