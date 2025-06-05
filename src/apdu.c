#include "apdu.h"

#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "apdu_commands.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"
#include "queue.h"
#include "smartcard.h"
#include "tasks.h"

apdu_buffer_t apdu_handle(const apdu_buffer_t* apdu_buffer) {
  static uint8_t apdu_tx_buffer_data[APDU_MAX_TX_PACKET_SIZE] = {0};
  apdu_buffer_t apdu_tx_buffer = {
      .data = apdu_tx_buffer_data,
      .data_len = 0,
  };

  apdu_packet_t apdu_packet;
  if (!apdu_parse(apdu_buffer, &apdu_packet)) {
    apdu_build_response(&apdu_tx_buffer, APDU_SW_CLASS_NOT_SUPPORTED, NULL, 0);
    return apdu_tx_buffer;
  }

  switch (apdu_packet.ins) {
    case APDU_INS_HASH_MD5: {
      uint8_t md5_digest[16];

      int ret = mbedtls_md5_ret(apdu_packet.data, apdu_packet.lc, md5_digest);
      if (ret != 0) {
        apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
        return apdu_tx_buffer;
      }

      apdu_build_response(&apdu_tx_buffer, APDU_SW_OK, md5_digest, sizeof(md5_digest));
      return apdu_tx_buffer;
    }

    case APDU_INS_HASH_SHA256: {
      uint8_t sha256_digest[32];

      int ret = mbedtls_sha256_ret(apdu_packet.data, apdu_packet.lc, sha256_digest, 0);
      if (ret != 0) {
        apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
        return apdu_tx_buffer;
      }

      apdu_build_response(&apdu_tx_buffer, APDU_SW_OK, sha256_digest, sizeof(sha256_digest));
      return apdu_tx_buffer;
    }

    case APDU_INS_INITIALIZE_WALLET: {
      smartcard_command_t cmd = SMARTCARD_INITIALIZE_WALLET;
      xQueueOverwrite(smartcard_rx_queue, &cmd);

      smartcard_response_t response;
      if (xQueueReceive(smartcard_tx_queue, &response, portMAX_DELAY) != pdPASS) {
        apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
        return apdu_tx_buffer;
      }

      apdu_build_response(&apdu_tx_buffer,
                          response.status == SMARTCARD_STATUS_ERROR ? APDU_SW_INSTR_NOT_SUPPORTED : APDU_SW_WAITING,
                          &response.data, response.data_len);

      return apdu_tx_buffer;
    }

    case APDU_INS_RESET_WALLET: {
      smartcard_command_t cmd = SMARTCARD_RESET_WALLET;
      xQueueOverwrite(smartcard_rx_queue, &cmd);

      smartcard_response_t response;
      if (xQueueReceive(smartcard_tx_queue, &response, portMAX_DELAY) != pdPASS) {
        apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
        return apdu_tx_buffer;
      }

      apdu_build_response(&apdu_tx_buffer,
                          response.status == SMARTCARD_STATUS_ERROR ? APDU_SW_INSTR_NOT_SUPPORTED : APDU_SW_OK,
                          &response.data, response.data_len);

      return apdu_tx_buffer;
    }
  }

  apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
  return apdu_tx_buffer;
}
