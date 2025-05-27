#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

typedef struct {
  uint8_t* data;
  uint8_t data_len;
} flash_buffer_t;

extern QueueHandle_t flash_rx_queue;

void flash_writer_task(void* pvParams);
