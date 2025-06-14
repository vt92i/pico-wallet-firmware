#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pico/flash.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "mbedtls/platform_util.h"

#include "bip/bip39.h"
#include "smartcard/commands/smartcard_commands.h"
#include "smartcard/smartcard.h"
#include "utils/flash.h"

QueueHandle_t smartcard_rx_queue, smartcard_tx_queue;

void smartcard_handler_task(void* pvParams) {
  (void)pvParams;

  smartcard_request_t request;
  smartcard_response_t response;

  for (;;) {
    if (xQueueReceive(smartcard_rx_queue, &request, portMAX_DELAY) == pdPASS) {
      switch (request.command) {
        case SMARTCARD_INITIALIZE_WALLET: {
          response.data_len = 0;

          if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};
          if (smartcard_initialize_wallet(mnemonic) != SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
            response.data_len += (uint8_t)strlen(mnemonic[i]);
            if (i < BIP39_MNEMONIC_LENGTH - 1) response.data_len += 1;
          }

          response.data = pvPortMalloc(response.data_len + 1);
          if (response.data == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            response.data = NULL;
            response.data_len = 0;

            xQueueOverwrite(smartcard_tx_queue, &response);
            mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
            break;
          }

          response.data[0] = '\0';
          for (size_t i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
            response.data = (uint8_t*)strcat((char*)response.data, mnemonic[i]);
            if (i < BIP39_MNEMONIC_LENGTH - 1) response.data = (uint8_t*)strcat((char*)response.data, " ");
          }
          response.status = SMARTCARD_STATUS_OK;

          xQueueOverwrite(smartcard_tx_queue, &response);

          mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
          vPortFree(response.data);

          break;
        }

        case SMARTCARD_RESET_WALLET: {
          int rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
          if (rc != 0) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.status = SMARTCARD_STATUS_OK;
          xQueueOverwrite(smartcard_tx_queue, &response);
          break;
        }

        case SMARTCARD_GET_WALLET_STATUS: {
          break;
        }

        case SMARTCARD_GET_ADDRESS: {
          break;
        }

        case SMARTCARD_GET_PUBLIC_KEY: {
          break;
        }

        case SMARTCARD_SIGN_TRANSACTION: {
          break;
        }
      }
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
