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
        case SMARTCARD_UNLOCK: {
          response.data_len = 0;
          if (smartcard_get_wallet_status() != SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          const char* password = (const char*)request.data;
          uint8_t password_len = (uint8_t)strlen(password);

          if (smartcard_unlock(password, password_len) != SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.status = SMARTCARD_STATUS_OK;
          xQueueOverwrite(smartcard_tx_queue, &response);
          break;
        }

        case SMARTCARD_INITIALIZE_WALLET: {
          response.data_len = 0;

          if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          const char* password = (const char*)request.data;
          uint8_t password_len = (uint8_t)strlen(password);

          char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};
          if (smartcard_initialize_wallet(password, password_len, mnemonic) != SMARTCARD_STATUS_OK) {
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

        case SMARTCARD_RESTORE_WALLET: {
          response.data_len = 0;

          if (smartcard_get_wallet_status() == SMARTCARD_STATUS_OK) {
            response.status = SMARTCARD_STATUS_ERROR;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};

          char* token = strtok((char*)request.data, " ");
          for (size_t i = 0; token != NULL && i < BIP39_MNEMONIC_LENGTH; i++, token = strtok(NULL, " ")) {
            mnemonic[i] = token;
            printf("Mnemonic[%zu]: %s\n", i, mnemonic[i]);
          }

          // token = strtok(NULL, " ");
          const char* password = (const char*)token;
          uint8_t password_len = (uint8_t)strlen(password);

          response.status = smartcard_restore_wallet(password, password_len, (const char**)mnemonic);
          xQueueOverwrite(smartcard_tx_queue, &response);

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
          response.status = smartcard_get_wallet_status();

          response.data = pvPortMalloc(1);
          if (response.data == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            response.data_len = 0;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.data[0] = response.status == SMARTCARD_STATUS_OK ? 0x01 : 0x00;
          response.data_len = 1;

          xQueueOverwrite(smartcard_tx_queue, &response);
          vPortFree(response.data);

          break;
        }

        case SMARTCARD_GET_ADDRESS: {
          uint8_t index = request.data[0];

          char address[BIP84_ADDRESS_SIZE] = {0};
          response.status = smartcard_get_address(index, address);

          if (response.status != SMARTCARD_STATUS_OK) {
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.data_len = (uint8_t)strlen(address);
          response.data = pvPortMalloc(response.data_len);

          if (response.data == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            response.data_len = 0;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          memcpy(response.data, address, response.data_len);
          xQueueOverwrite(smartcard_tx_queue, &response);
          vPortFree(response.data);

          break;
        }

        case SMARTCARD_GET_PUBLIC_KEY: {
          uint8_t index = request.data[0];

          uint8_t public_key[BIP84_PUBLIC_KEY_SIZE] = {0};
          response.status = smartcard_get_public_key(index, public_key);

          if (response.status != SMARTCARD_STATUS_OK) {
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.data_len = sizeof(public_key);
          response.data = pvPortMalloc(response.data_len);

          if (response.data == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            response.data_len = 0;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          memcpy(response.data, public_key, response.data_len);
          xQueueOverwrite(smartcard_tx_queue, &response);
          vPortFree(response.data);

          break;
        }

        case SMARTCARD_SIGN_TRANSACTION: {
          uint8_t signature[86] = {0};
          size_t signature_len = 0;

          response.status = smartcard_sign_transaction(request.data[0], request.data + 1, signature, &signature_len);
          if (response.status != SMARTCARD_STATUS_OK) {
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          response.data_len = (uint16_t)signature_len;
          response.data = pvPortMalloc(response.data_len);

          if (response.data == NULL) {
            response.status = SMARTCARD_STATUS_ERROR;
            response.data_len = 0;
            xQueueOverwrite(smartcard_tx_queue, &response);
            break;
          }

          memcpy(response.data, signature, response.data_len);
          xQueueOverwrite(smartcard_tx_queue, &response);
          vPortFree(response.data);

          break;
        }
      }
    }
  }
}
