#pragma once

#include "apdu.h"

bool handle_initialize_wallet(const apdu_packet_t* packet, apdu_buffer_t* response);
bool handle_reset_wallet(const apdu_packet_t* packet, apdu_buffer_t* response);
