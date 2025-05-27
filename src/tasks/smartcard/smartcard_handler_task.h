#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

extern QueueHandle_t smartcard_rx_queue, smartcard_tx_queue;

void smartcard_handler_task(void* pvParams);
