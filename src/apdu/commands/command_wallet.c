#include "command_wallet.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

#include "apdu_utils.h"
#include "smartcard.h"
#include "tasks.h"

bool handle_initialize_wallet(const apdu_packet_t* packet, apdu_buffer_t* response) {
  smartcard_command_t cmd = SMARTCARD_INITIALIZE_WALLET;
  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    apdu_build_response(response, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
    return false;
  }

  apdu_build_response(response, resp.status == SMARTCARD_STATUS_ERROR ? APDU_SW_INSTR_NOT_SUPPORTED : APDU_SW_WAITING,
                      &resp.data, resp.data_len);
  return true;
}

bool handle_reset_wallet(const apdu_packet_t* packet, apdu_buffer_t* response) {
  smartcard_command_t cmd = SMARTCARD_RESET_WALLET;
  xQueueOverwrite(smartcard_rx_queue, &cmd);

  smartcard_response_t resp;
  if (xQueueReceive(smartcard_tx_queue, &resp, portMAX_DELAY) != pdPASS) {
    apdu_build_response(response, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
    return false;
  }

  apdu_build_response(response, resp.status == SMARTCARD_STATUS_ERROR ? APDU_SW_INSTR_NOT_SUPPORTED : APDU_SW_OK,
                      &resp.data, resp.data_len);
  return true;
}
