#include "apdu_utils.h"

#include <stdint.h>
#include <string.h>

bool apdu_parse(const apdu_buffer_t* apdu_buffer, apdu_packet_t* packet) {
  if (apdu_buffer->data == NULL || packet == NULL || apdu_buffer->data_len < (APDU_HEADER_SIZE + 1)) return false;

  packet->cla = apdu_buffer->data[0];
  packet->ins = apdu_buffer->data[1];
  packet->p1 = apdu_buffer->data[2];
  packet->p2 = apdu_buffer->data[3];

  // if (apdu_buffer->data[4] > APDU_MAX_DATA_LEN) return false;
  packet->lc = apdu_buffer->data[4];

  uint16_t required_len = (uint16_t)(APDU_HEADER_SIZE + 1 + packet->lc + (packet->lc > 0 ? 1 : 0));
  if (apdu_buffer->data_len < required_len) return false;

  packet->data = (packet->lc > 0) ? &apdu_buffer->data[APDU_HEADER_SIZE + 1] : NULL;
  packet->le = (packet->lc > 0) ? apdu_buffer->data[APDU_HEADER_SIZE + 1 + packet->lc] : 0;

  return true;
}

void apdu_build_response(apdu_buffer_t* apdu_buffer, apdu_sw_t status, const uint8_t* data, uint16_t data_len) {
  if (apdu_buffer == NULL) return;

  if (data_len > 0 && data_len < APDU_MAX_DATA_LEN && data != NULL) memcpy(apdu_buffer->data, data, data_len);

  apdu_buffer->data[data_len] = (uint8_t)((status >> 8) & 0xFF);
  apdu_buffer->data[data_len + 1] = (uint8_t)(status & 0xFF);
  apdu_buffer->data_len = data_len + 2;
}
