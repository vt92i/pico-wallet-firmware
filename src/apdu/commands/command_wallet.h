#pragma once

#include "apdu/apdu.h"

#define APDU_SW_WAITING ((apdu_sw_t)0x6000)

bool handle_initialize_wallet(const apdu_packet_t* packet, apdu_buffer_t* response);
bool handle_reset_wallet(const apdu_packet_t* packet, apdu_buffer_t* response);
