#include <hardware/gpio.h>
#include <stdint.h>
#include <stdlib.h>

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "FreeRTOSConfig.h"
#include "apdu.h"
#include "bip39.h"
#include "bsp/board_api.h"
#include "pico/multicore.h"
#include "queue.h"
#include "smartcard.h"
#include "ssd1306.h"
#include "task.h"

#define QUEUE_LENGTH 8

static QueueHandle_t usb_rx_queue, usb_tx_queue;

static void usb_reader_task(void* pvParams) {
  (void)pvParams;

  uint8_t apdu_rx_buffer_data[APDU_MAX_RX_PACKET_SIZE] = {0};
  apdu_buffer_t apdu_rx_buffer = {
      .data = apdu_rx_buffer_data,
      .data_len = 0,
  };

  uint16_t buffer_offset = 0;

  for (;;) {
    tud_task();  // TinyUSB device task to handle USB events

    if (tud_cdc_connected()) {
      if (tud_cdc_available()) {
        board_led_on();

        // Read available data into the buffer
        uint32_t read_len =
            tud_cdc_read(apdu_rx_buffer.data + buffer_offset, sizeof(apdu_rx_buffer_data) - buffer_offset);
        buffer_offset += read_len;  // if read_len is < 64 and buffer_offset is 0, it means data is complete?

        // Wait until we have at least header to extract Lc
        if (buffer_offset >= APDU_HEADER_SIZE + 1 && apdu_rx_buffer.data_len == 0) {
          uint8_t lc = apdu_rx_buffer.data[4];  // Lc is at offset 4
          apdu_rx_buffer.data_len = APDU_HEADER_SIZE + 1 /* Lc */ + lc + 1 /* Le */;
        }

        // Wait until full APDU command is received
        if (apdu_rx_buffer.data_len > 0 && buffer_offset >= apdu_rx_buffer.data_len) {
          xQueueSend(usb_rx_queue, &apdu_rx_buffer, portMAX_DELAY);
          apdu_rx_buffer.data_len = 0;  // Reset data length
          buffer_offset = 0;            // Reset buffer offset
        }
      } else {
        board_led_off();
        if (buffer_offset > 0 || apdu_rx_buffer.data_len > 0) {
          apdu_rx_buffer.data_len = 0;  // Reset data length
          buffer_offset = 0;            // Reset buffer offset

          xQueueSend(usb_rx_queue, &apdu_rx_buffer, portMAX_DELAY);
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

static void usb_writer_task(void* pvParams) {
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

static void apdu_handler_task(void* pvParams) {
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

static void lcd_task(void* pvParams) {
  (void)pvParams;

  ssd1306_t disp;
  disp.external_vcc = false;

  ssd1306_init(&disp, 128, 32, 0x3C, i2c_default);
  ssd1306_clear(&disp);

  for (;;) {
    // for (size_t i = 0; i < 64; ++i) {
    //   ssd1306_draw_string(&disp, 0, 0, 1, BIP39_WORDS[i]);
    //   ssd1306_show(&disp);
    //   vTaskDelay(pdMS_TO_TICKS(500));
    //   ssd1306_clear(&disp);
    // }

    if (!gpio_get(16)) {
      ssd1306_draw_string(&disp, 0, 0, 1, "1");
      board_led_on();
    } else {
      ssd1306_draw_string(&disp, 0, 0, 1, "0");
      board_led_off();
    }

    ssd1306_show(&disp);
    ssd1306_clear(&disp);

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

#define LCD_SDA_PIN PICO_DEFAULT_I2C_SDA_PIN
#define LCD_SCL_PIN PICO_DEFAULT_I2C_SCL_PIN
#define BUTTON_PIN  16

void setup_gpios(void) {
  // Initialize I2C
  i2c_init(i2c_default, 400 * 1000);  // 400 kHz I2C speed
  gpio_set_function(LCD_SDA_PIN, GPIO_FUNC_I2C);
  gpio_set_function(LCD_SCL_PIN, GPIO_FUNC_I2C);
  gpio_pull_up(LCD_SCL_PIN);
  gpio_pull_up(LCD_SDA_PIN);

  // Initialize  GPIO
  gpio_init(BUTTON_PIN);
  gpio_set_function(BUTTON_PIN, GPIO_FUNC_SIO);
  gpio_set_dir(BUTTON_PIN, GPIO_IN);
  gpio_pull_up(BUTTON_PIN);
}

#if (configCHECK_FOR_STACK_OVERFLOW > 0)
void vApplicationStackOverflowHook(TaskHandle_t xTask, char* pcTaskName) {
  // This function will be called when a stack overflow is detected.
  // You can place a breakpoint here or log the error.
  taskDISABLE_INTERRUPTS();
  printf("Stack overflow in task: %s\n", pcTaskName);
  for (;;);
}
#endif /* configCHECK_FOR_STACK_OVERFLOW > 0 */

// void print_buf(const uint8_t* buf, size_t len) {
//   for (size_t i = 0; i < len; ++i) {
//     printf("%02x", buf[i]);
//     if (i % 16 == 15)
//       printf("\n");
//     else
//       printf(" ");
//   }
// }

static void flash_task(void* pvParams) {
  (void)pvParams;

  // Wait for the USB tasks to be ready
  vTaskDelay(pdMS_TO_TICKS(1000));

  // uint8_t random_data[FLASH_PAGE_SIZE];
  // for (uint i = 0; i < FLASH_PAGE_SIZE; ++i) random_data[i] = rand() >> 16;
  //
  // printf("Generated random data:\n");
  // print_buf(random_data, FLASH_PAGE_SIZE);

  // Note that a whole number of sectors must be erased at a time.
  // printf("\nErasing target region...\n");
  // board_led_on();
  //
  // int rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
  //
  // board_led_off();
  // printf("status code: %d\n", rc);

  // printf("Done. Read back target region:\n");
  // print_buf(flash_target_contents, FLASH_PAGE_SIZE);

  // printf("\nProgramming target region...\n");
  // uintptr_t params[] = {FLASH_TARGET_OFFSET, (uintptr_t)random_data};
  // rc = flash_safe_execute(call_flash_range_program, params, UINT32_MAX);
  // hard_assert(rc == PICO_OK);
  // printf("Done. Read back target region:\n");
  // print_buf(flash_target_contents, FLASH_PAGE_SIZE);
  //
  // bool mismatch = false;
  // for (uint i = 0; i < FLASH_PAGE_SIZE; ++i) {
  //   if (random_data[i] != flash_target_contents[i]) mismatch = true;
  // }
  // if (mismatch)
  //   printf("Programming failed!\n");
  // else
  //   printf("Programming successful!\n");
}

int main(void) {
  board_init();
  tusb_init();

  setup_gpios();

  generate_mnemonic();  // Generate and print mnemonic for debugging

  usb_rx_queue = xQueueCreate(QUEUE_LENGTH, sizeof(apdu_buffer_t));
  usb_tx_queue = xQueueCreate(QUEUE_LENGTH, sizeof(apdu_buffer_t));

  if (usb_rx_queue == NULL || usb_tx_queue == NULL) {
    printf("Failed to create USB queues\n");
    return -1;  // Exit if queue creation fails
  }

  // xTaskCreate(flash_task, "Flash Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);

  xTaskCreate(usb_reader_task, "USB Reader Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 8UL, NULL);
  xTaskCreate(usb_writer_task, "USB Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 8UL, NULL);

  xTaskCreate(apdu_handler_task, "APDU Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 6UL, NULL);
  xTaskCreate(lcd_task, "LCD Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 4UL, NULL);

  // Start FreeRTOS scheduler
  vTaskStartScheduler();

  /* ---------------------------------------------------------+
   * Should never reach here, as the scheduler will take over.
   * If for some reason it does, then you fucked up something.
   * ---------------------------------------------------------+*/
  for (;;);
}
