
#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "apdu/apdu.h"
#include "bsp/board_api.h"  // IWYU pragma: keep

QueueHandle_t usb_tx_queue;

void usb_writer_task(void* pvParams) {
  (void)pvParams;

  apdu_buffer_t apdu_tx_buffer;

  for (;;) {
    if (xQueueReceive(usb_tx_queue, &apdu_tx_buffer, portMAX_DELAY) == pdPASS) {
      tud_cdc_write(apdu_tx_buffer.data, apdu_tx_buffer.data_len);
      tud_cdc_write_flush();
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
