#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hardware/gpio.h"
#include "pico/flash.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "mbedtls/platform_util.h"

#include "bip/bip39.h"
#include "smartcard/smartcard.h"
#include "ssd1306/ssd1306.h"
#include "tasks/flash/flash_writer_task.h"
#include "tasks/tasks.h"
#include "utils/flash.h"

QueueHandle_t smartcard_rx_queue, smartcard_tx_queue;

void smartcard_handler_task(void* pvParams) {
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
