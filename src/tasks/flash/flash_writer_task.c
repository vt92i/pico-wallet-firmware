#include "hardware/flash.h"
#include "pico/flash.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "bip/bip39.h"
#include "bsp/board_api.h"
#include "utils/flash.h"

QueueHandle_t flash_rx_queue;

void flash_writer_task(void* pvParams) {
  (void)pvParams;

  for (;;) {
    uint8_t seed[BIP39_SEED_SIZE] = {0};

    if (xQueueReceive(flash_rx_queue, &seed, portMAX_DELAY) == pdPASS) {
      board_led_on();

      uint8_t buffer[FLASH_PAGE_SIZE] __attribute__((aligned(4))) = {0};
      buffer[0] = 0x01;  // Magic byte to indicate there is a seed stored
      memcpy(buffer + 1, seed, BIP39_SEED_SIZE);

      int rc;
      rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
      hard_assert(rc == PICO_OK);

      uintptr_t params[] = {FLASH_TARGET_OFFSET, (uintptr_t)buffer};
      rc = flash_safe_execute(call_flash_range_program, params, UINT32_MAX);
      hard_assert(rc == PICO_OK);

      board_led_off();
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
