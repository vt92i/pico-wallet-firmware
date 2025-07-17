#include "command_wallet.h"

#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

#include "rpc/rpc.h"
#include "rpc/rpc_utils.h"
#include "smartcard/commands/smartcard_commands.h"
#include "smartcard/smartcard.h"
#include "tasks/smartcard/smartcard_handler_task.h"

bool handle_initialize_wallet(const rpc_payload_t* payload, rpc_buffer_t* response) {
  (void)payload;

  smartcard_request_t req = {
      .command = SMARTCARD_INITIALIZE_WALLET,
  };
  xQueueOverwrite(smartcard_rx_queue, &req);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  switch (resp.status) {
    case SMARTCARD_STATUS_OK:
      rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);
      break;
    case SMARTCARD_STATUS_ERROR:
      rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
      break;
  }

  return true;
}

bool handle_restore_wallet(const rpc_payload_t* payload, rpc_buffer_t* response) {
  smartcard_request_t req = {
      .command = SMARTCARD_RESTORE_WALLET,
      .data = (uint8_t*)payload->data,
      .data_len = payload->data_len,
  };

  xQueueOverwrite(smartcard_rx_queue, &req);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  switch (resp.status) {
    case SMARTCARD_STATUS_OK:
      rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);
      break;
    case SMARTCARD_STATUS_ERROR:
      rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
      break;
  }

  return true;
}

bool handle_reset_wallet(const rpc_payload_t* payload, rpc_buffer_t* response) {
  (void)payload;

  smartcard_request_t cmd = {
      .command = SMARTCARD_RESET_WALLET,
  };
  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  rpc_build_response(response, resp.status == SMARTCARD_STATUS_OK ? RPC_STATUS_OK : RPC_STATUS_EXECUTION_ERROR, NULL,
                     0);
  return true;
}

bool handle_get_wallet_status(const rpc_payload_t* payload, rpc_buffer_t* response) {
  (void)payload;

  smartcard_request_t cmd = {
      .command = SMARTCARD_GET_WALLET_STATUS,
  };
  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);

  return true;
}

bool handle_get_address(const rpc_payload_t* payload, rpc_buffer_t* response) {
  smartcard_request_t cmd = {
      .command = SMARTCARD_GET_ADDRESS,
      .data = (uint8_t*)payload->data,
      .data_len = payload->data_len,
  };

  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  switch (resp.status) {
    case SMARTCARD_STATUS_OK:
      rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);
      break;
    case SMARTCARD_STATUS_ERROR:
      rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
      break;
  }

  return true;
}

bool handle_get_public_key(const rpc_payload_t* payload, rpc_buffer_t* response) {
  smartcard_request_t cmd = {
      .command = SMARTCARD_GET_PUBLIC_KEY,
      .data = (uint8_t*)payload->data,
      .data_len = payload->data_len,
  };

  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  switch (resp.status) {
    case SMARTCARD_STATUS_OK:
      rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);
      break;
    case SMARTCARD_STATUS_ERROR:
      rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
      break;
  }

  return true;
}

bool handle_sign_transaction(const rpc_payload_t* payload, rpc_buffer_t* response) {
  smartcard_request_t cmd = {
      .command = SMARTCARD_SIGN_TRANSACTION,
      .data = (uint8_t*)payload->data,
      .data_len = payload->data_len,
  };

  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  switch (resp.status) {
    case SMARTCARD_STATUS_OK:
      rpc_build_response(response, RPC_STATUS_OK, resp.data, resp.data_len);
      break;
    case SMARTCARD_STATUS_ERROR:
      rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
      break;
  }

  return true;
}
