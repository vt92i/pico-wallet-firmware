#pragma once

#include <stdbool.h>
#include <stdint.h>

#define RPC_HEADER_SIZE        (2)
#define RPC_CMD_SIZE           (1)
#define RPC_STATUS_SIZE        (2)

#define RPC_MAX_DATA_LEN       (512)
#define RPC_MAX_RX_PACKET_SIZE (RPC_HEADER_SIZE + RPC_CMD_SIZE + RPC_MAX_DATA_LEN)
#define RPC_MAX_TX_PACKET_SIZE (RPC_HEADER_SIZE + RPC_STATUS_SIZE + RPC_MAX_DATA_LEN)

typedef enum {
  RPC_STATUS_OK = 0x9000,
  RPC_STATUS_EXECUTION_ERROR = 0x6F00,

  RPC_STATUS_INVALID_COMMAND = 0x6D00,
} rpc_status_t;

typedef struct {
  uint8_t* data;
  uint16_t data_len;
} rpc_buffer_t;

typedef struct {
  const uint8_t* data;
  uint16_t data_len;
} rpc_payload_t;
