#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "rpc/rpc.h"
#include "tusb.h"  // IWYU pragma: keep

QueueHandle_t usb_tx_queue;

void usb_writer_task(void* pvParams) {
  (void)pvParams;

  rpc_buffer_t tx_buffer;

  for (;;) {
    if (xQueueReceive(usb_tx_queue, &tx_buffer, portMAX_DELAY) == pdPASS) {
      tud_cdc_write(tx_buffer.data, RPC_HEADER_SIZE + RPC_STATUS_SIZE + tx_buffer.data_len);
      tud_cdc_write_flush();
    }
  }
}
