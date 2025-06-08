#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

extern QueueHandle_t usb_rx_queue;

void usb_reader_task(void* pvParams);
