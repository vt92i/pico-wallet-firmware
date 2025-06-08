#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "apdu/apdu.h"
#include "apdu/apdu_dispatch.h"
#include "tasks/usb/usb_reader_task.h"
#include "tasks/usb/usb_writer_task.h"

void apdu_handler_task(void* pvParams) {
  (void)pvParams;

  apdu_buffer_t apdu_rx_buffer, apdu_tx_buffer;

  for (;;) {
    if (xQueueReceive(usb_rx_queue, &apdu_rx_buffer, portMAX_DELAY) == pdPASS) {
      apdu_tx_buffer = apdu_handle(&apdu_rx_buffer);
      xQueueSend(usb_tx_queue, &apdu_tx_buffer, portMAX_DELAY);
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
