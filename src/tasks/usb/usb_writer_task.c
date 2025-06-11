
#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "bsp/board_api.h"  // IWYU pragma: keep
#include "rpc/rpc.h"

QueueHandle_t usb_tx_queue;

void usb_writer_task(void* pvParams) {
  (void)pvParams;

  rpc_buffer_t tx_buffer;

  for (;;) {
    if (xQueueReceive(usb_tx_queue, &tx_buffer, portMAX_DELAY) == pdPASS) {
      printf("USB Writer Task: Sending %d bytes\n", tx_buffer.data_len + RPC_HEADER_SIZE + RPC_STATUS_SIZE);
      for (uint16_t i = 0; i < tx_buffer.data_len + RPC_HEADER_SIZE + RPC_STATUS_SIZE; i++) {
        printf("%02x", tx_buffer.data[i]);
      }
      printf("\n");

      tud_cdc_write(tx_buffer.data, RPC_HEADER_SIZE + RPC_STATUS_SIZE + tx_buffer.data_len);
      tud_cdc_write_flush();
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
