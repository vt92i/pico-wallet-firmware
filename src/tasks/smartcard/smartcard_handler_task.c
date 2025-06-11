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

  smartcard_command_t command;
  smartcard_response_t response = {
      .data = NULL,
      .data_len = 0,
  };

  for (;;) {
    if (xQueueReceive(smartcard_rx_queue, &command, portMAX_DELAY) == pdPASS) {
      switch (command) {
        case SMARTCARD_INITIALIZE_WALLET: {
          response.data_len = 0;

          if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            printf("Wallet already initialized.\n");
            break;
          }

          char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};
          if (smartcard_initialize_wallet(mnemonic) != SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            printf("Failed to initialize wallet.\n");
            break;
          }

          printf("Mnemonic:\n");
          for (int i = 0; i < BIP39_MNEMONIC_LENGTH; ++i) {
            printf("%s ", mnemonic[i]);
          }
          printf("\n");

          size_t total_len = 0;
          for (int i = 0; i < 24; ++i) {
            total_len += strlen(mnemonic[i]);
            if (i < 23) total_len += 1;
          }

          char* combined_mnemonic = pvPortMalloc(total_len + 1);
          if (combined_mnemonic == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            printf("Memory allocation failed for mnemonic.\n");
            mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
            break;
          }

          combined_mnemonic[0] = '\0';
          for (int i = 0; i < BIP39_MNEMONIC_LENGTH; ++i) {
            strcat(combined_mnemonic, mnemonic[i]);
            if (i < BIP39_MNEMONIC_LENGTH - 1) strcat(combined_mnemonic, " ");
          }

          uint8_t* mnemonic_byte = (uint8_t*)combined_mnemonic;

          printf("hex mnemonic: %d bytes\n", total_len);
          for (size_t i = 0; i < total_len; ++i) {
            printf("%02x", mnemonic_byte[i]);
          }
          printf("\n");

          response.status = SMARTCARD_STATUS_OK;
          response.data = mnemonic_byte;
          response.data_len = (uint8_t)total_len;

          xQueueOverwrite(smartcard_tx_queue, &response);
          printf("Wallet initialized successfully.\n");

          // mbedtls_platform_zeroize(mnemonic, sizeof(char*) * BIP39_MNEMONIC_LENGTH);
          // mbedtls_platform_zeroize(combined_mnemonic, total_len + 1);
          vPortFree(combined_mnemonic);

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

        default: {
          response.status = SMARTCARD_STATUS_ERROR;
          response.data = NULL;
          response.data_len = 0;
          xQueueOverwrite(smartcard_tx_queue, &response);
          break;
        }
      }
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
