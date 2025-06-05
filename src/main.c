#include <stdint.h>

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "apdu.h"
#include "bip32.h"
#include "bip39.h"
#include "bsp/board_api.h"
#include "flash.h"
#include "hardware/flash.h"
#include "hardware/gpio.h"
#include "mbedtls/platform_util.h"
#include "pico/flash.h"
#include "queue.h"
#include "smartcard.h"
#include "ssd1306.h"
#include "task.h"
#include "tasks.h"

QueueHandle_t usb_rx_queue, usb_tx_queue;
QueueHandle_t smartcard_rx_queue, smartcard_tx_queue;
QueueHandle_t flash_rx_queue;

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

static void smartcard_handler_task(void* pvParams) {
  (void)pvParams;

  smartcard_command_t command;
  smartcard_response_t response;

  ssd1306_t display;
  display.external_vcc = false;

  ssd1306_init(&display, 128, 32, 0x3C, i2c_default);
  ssd1306_clear(&display);
  ssd1306_show(&display);

  for (;;) {
    if (xQueueReceive(smartcard_rx_queue, &command, portMAX_DELAY) == pdPASS) {
      switch (command) {
        case SMARTCARD_INITIALIZE_WALLET: {
          static uint8_t state = 0;

          response.status = SMARTCARD_STATUS_PROCESSING;
          response.data = state;
          response.data_len = 1;

          if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          static char* mnemonic[BIP39_MNEMONIC_LENGTH];
          if (state == 0 && !generate_mnemonic(mnemonic)) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          if (state == 0) xQueueOverwrite(smartcard_tx_queue, &response);

          while (state < BIP39_MNEMONIC_LENGTH) {
            char index[4];
            snprintf(index, sizeof(index), "%d.", state + 1);

            ssd1306_clear(&display);
            ssd1306_draw_string(&display, (128 - (strlen(index) * (8 + 2) - 2)) / 2, 0, 1, index);
            ssd1306_draw_string(&display, (128 - (strlen(mnemonic[state]) * (8 + 2) - 2)) / 2, 16, 1, mnemonic[state]);
            ssd1306_show(&display);

            while (gpio_get(BUTTON_PIN)) {
              xQueueOverwrite(smartcard_tx_queue, &response);
              vTaskDelay(pdMS_TO_TICKS(10));
            }

            xQueueOverwrite(smartcard_tx_queue, &response);

            state++;
            response.status = SMARTCARD_STATUS_PROCESSING;
            response.data = state;

            vTaskDelay(pdMS_TO_TICKS(200));
          }

          uint8_t seed[BIP39_SEED_SIZE];
          if (!generate_seed((const char*)mnemonic, seed)) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
          xQueueSend(flash_rx_queue, &seed, portMAX_DELAY);
          mbedtls_platform_zeroize(seed, sizeof(seed));

          response.status = SMARTCARD_STATUS_OK;
          xQueueOverwrite(smartcard_tx_queue, &response);

          ssd1306_clear(&display);
          ssd1306_show(&display);

          break;
        }

        case SMARTCARD_RESET_WALLET: {
          response.data = 0;
          response.data_len = 0;

          int rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
          if (rc != PICO_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.status = SMARTCARD_STATUS_OK;
          xQueueOverwrite(smartcard_tx_queue, &response);

          ssd1306_clear(&display);
          ssd1306_show(&display);

          break;
        }

        default: {
          response.status = SMARTCARD_STATUS_ERROR;
          response.data = 0;
          response.data_len = 0;
          xQueueOverwrite(smartcard_tx_queue, &response);
          break;
        }
      }
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

static void flash_writer_task(void* pvParams) {
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

static void runit(void) {
  board_init();
  tusb_init();

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

int main(void) {
  runit();

  usb_rx_queue = xQueueCreate(QUEUE_LENGTH, sizeof(apdu_buffer_t));
  usb_tx_queue = xQueueCreate(QUEUE_LENGTH, sizeof(apdu_buffer_t));

  smartcard_rx_queue = xQueueCreate(1, sizeof(smartcard_command_t));
  smartcard_tx_queue = xQueueCreate(1, sizeof(smartcard_response_t));

  flash_rx_queue = xQueueCreate(1, BIP39_SEED_SIZE);

  xTaskCreate(flash_writer_task, "Flash Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 12UL, NULL);

  xTaskCreate(usb_reader_task, "USB Reader Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);
  xTaskCreate(usb_writer_task, "USB Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);

  xTaskCreate(apdu_handler_task, "APDU Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 8UL, NULL);
  xTaskCreate(smartcard_handler_task, "Smartcard Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 6UL,
              NULL);

  // Start FreeRTOS scheduler
  vTaskStartScheduler();

  /* ---------------------------------------------------------+
   * Should never reach here, as the scheduler will take over.
   * If for some reason it does, then you fucked up something.
   * ---------------------------------------------------------+*/
  for (;;);
}
