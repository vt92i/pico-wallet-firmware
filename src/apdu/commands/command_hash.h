#pragma once

#include "apdu.h"

bool handle_md5(const apdu_packet_t* packet, apdu_buffer_t* response);
bool handle_sha256(const apdu_packet_t* packet, apdu_buffer_t* response);
