
#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

extern QueueHandle_t usb_tx_queue;

void usb_writer_task(void* pvParams);
