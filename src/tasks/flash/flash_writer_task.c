#include "flash_writer_task.h"

#include "pico/flash.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "bsp/board_api.h"
#include "utils/flash.h"

QueueHandle_t flash_rx_queue;

void flash_writer_task(void* pvParams) {
  (void)pvParams;

  flash_buffer_t flash_buffer;

  for (;;) {
    if (xQueueReceive(flash_rx_queue, &flash_buffer, portMAX_DELAY) == pdPASS) {
      board_led_on();

      int rc;
      rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
      hard_assert(rc == PICO_OK);

      if (flash_buffer.data_len > 0) {
        uint8_t buffer[FLASH_PAGE_SIZE] __attribute__((aligned(4))) = {0};
        buffer[0] = 0x01;  // Magic Byte
        memcpy(buffer + 1, flash_buffer.data, flash_buffer.data_len);

        uintptr_t params[] = {FLASH_TARGET_OFFSET, (uintptr_t)buffer};
        rc = flash_safe_execute(call_flash_range_program, params, UINT32_MAX);
        hard_assert(rc == PICO_OK);

        vPortFree(flash_buffer.data);
      }

      board_led_off();
    }
  }
}
