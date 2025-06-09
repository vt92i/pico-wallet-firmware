#include <stdint.h>

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "apdu/apdu.h"
#include "bsp/board_api.h"

QueueHandle_t usb_rx_queue;

void usb_reader_task(void* pvParams) {
  (void)pvParams;

  uint8_t rx_buffer_data[APDU_MAX_RX_PACKET_SIZE] = {0};
  apdu_buffer_t rx_buffer = {
      .data = rx_buffer_data,
      .data_len = 0,
  };

  uint16_t buffer_offset = 0;

  for (;;) {
    tud_task();

    if (tud_cdc_connected()) {
      if (tud_cdc_available()) {
        board_led_on();

        uint32_t read_len = tud_cdc_read(rx_buffer.data + buffer_offset, sizeof(rx_buffer_data) - buffer_offset);
        buffer_offset += read_len;

        if (rx_buffer.data_len == 0 && buffer_offset >= APDU_HEADER_SIZE + 1) {
          uint8_t lc = rx_buffer.data[4];
          rx_buffer.data_len = APDU_HEADER_SIZE + 1 /* Lc */ + lc + 1 /* Le */;
          if (rx_buffer.data_len > sizeof(rx_buffer_data)) {
            rx_buffer.data_len = 0;
            buffer_offset = 0;
          }
        }

        if (rx_buffer.data_len > 0 && buffer_offset >= rx_buffer.data_len) {
          xQueueSend(usb_rx_queue, &rx_buffer, portMAX_DELAY);
          rx_buffer.data_len = 0;
          buffer_offset = 0;
        }
      } else
        board_led_off();
    } else
      board_led_off();

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
