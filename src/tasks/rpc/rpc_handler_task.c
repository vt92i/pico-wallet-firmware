#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "rpc/rpc.h"
#include "rpc/rpc_dispatch.h"
#include "tasks/usb/usb_reader_task.h"
#include "tasks/usb/usb_writer_task.h"

void rpc_handler_task(void* pvParams) {
  (void)pvParams;

  rpc_buffer_t rx_buffer, tx_buffer;

  for (;;) {
    if (xQueueReceive(usb_rx_queue, &rx_buffer, portMAX_DELAY) == pdPASS) {
      tx_buffer = rpc_handle(&rx_buffer);
      xQueueSend(usb_tx_queue, &tx_buffer, portMAX_DELAY);
    }
  }
}
