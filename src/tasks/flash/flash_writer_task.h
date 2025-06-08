#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

extern QueueHandle_t flash_rx_queue;

void flash_writer_task(void* pvParams);
