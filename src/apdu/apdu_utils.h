#pragma once

#include "apdu.h"

bool apdu_parse(const apdu_buffer_t* apdu_buffer, apdu_packet_t* packet);
void apdu_build_response(apdu_buffer_t* apdu_buffer, apdu_sw_t status, const uint8_t* data, uint16_t data_len);
