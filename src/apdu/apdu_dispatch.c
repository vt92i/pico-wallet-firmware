#include "apdu_dispatch.h"

#include <stddef.h>
#include <stdio.h>

#include "apdu_utils.h"

apdu_buffer_t apdu_handle(const apdu_buffer_t* apdu_buffer) {
  uint8_t apdu_tx_buffer_data[APDU_MAX_TX_PACKET_SIZE] = {0};
  apdu_buffer_t apdu_tx_buffer = {
      .data = apdu_tx_buffer_data,
      .data_len = 0,
  };

  apdu_packet_t packet;
  if (!apdu_parse(apdu_buffer, &packet)) {
    apdu_build_response(&apdu_tx_buffer, APDU_SW_CLASS_NOT_SUPPORTED, NULL, 0);
    return apdu_tx_buffer;
  }

  for (size_t i = 0; i < NUM_COMMAND_HANDLERS; i++) {
    if (command_handlers[i].ins == packet.ins) {
      if (command_handlers[i].handler(&packet, &apdu_tx_buffer)) return apdu_tx_buffer;
      break;
    }
  }

  apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
  return apdu_tx_buffer;
}
