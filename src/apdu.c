#include "apdu.h"

#include <stdint.h>
#include <string.h>

#include "apdu_commands.h"
#include "mbedtls/md5.h"

apdu_buffer_t apdu_handle(const apdu_buffer_t* apdu_buffer) {
  static uint8_t apdu_tx_buffer_data[APDU_MAX_TX_PACKET_SIZE] = {0};
  apdu_buffer_t apdu_tx_buffer = {
      .data = apdu_tx_buffer_data,
      .data_len = 0,
  };

  // const uint8_t enthropy[32] = {
  //     0X93, 0XDE, 0X2C, 0X95, 0X3A, 0XCD, 0XCC, 0X80, 0XEE, 0X72, 0X8B, 0XB0, 0XD9, 0X4E, 0XB8, 0X09,
  //     0XDA, 0X17, 0XD6, 0XCD, 0X2A, 0X3D, 0XFF, 0XD0, 0X37, 0X7C, 0XC8, 0X20, 0XDF, 0X58, 0X41, 0XE0,
  // };
  //
  // char* mnemonic[BIP39_MNEMONIC_LENGTH] = {0};  // Buffer for generated mnemonic words
  // char error_buf[255] = {0};                    // Buffer for error messages
  //
  // int ret = bip39_generate_mnemonic(enthropy, mnemonic, error_buf, sizeof(error_buf));
  //
  // if (ret != 0) {
  //   printf("Error generating mnemonic: %s\n", error_buf);
  //   write_status_word(APDU_SW_WRONG_DATA, resp.data);
  //   resp.data_len = 2;
  //   return resp;  // Return error status
  // }
  //
  // printf("Generated mnemonic:\n");
  // for (int i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
  //   if (mnemonic[i] != NULL) {
  //     printf("%s ", mnemonic[i]);
  //   } else {
  //     printf("(null) ");
  //   }
  // }
  // printf("\n");
  //
  // uint8_t seed[BIP39_SEED_SIZE];  // Buffer for the generated seed
  //
  // ret = bip39_generate_seed((const char**)mnemonic, seed, error_buf, sizeof(error_buf));
  //
  // if (ret != 0) {
  //   printf("Error generating seed: %s\n", error_buf);
  //   write_status_word(APDU_SW_WRONG_DATA, resp.data);
  //   resp.data_len = 2;
  // }
  //
  // printf("Generated seed:\n");
  // for (int i = 0; i < BIP39_SEED_SIZE; i++) {
  //   printf("%02x", seed[i]);
  // }
  // printf("\n");
  //
  // // Clear entropy, mnemonic, and seed buffers
  // mbedtls_platform_zeroize((void*)enthropy, sizeof(enthropy));
  // for (int i = 0; i < BIP39_MNEMONIC_LENGTH; i++) {
  //   if (mnemonic[i] != NULL) {
  //     mbedtls_platform_zeroize(mnemonic[i], strlen(mnemonic[i]));
  //   }
  // }
  // mbedtls_platform_zeroize(seed, sizeof(seed));

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
  }

  apdu_build_response(&apdu_tx_buffer, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
  return apdu_tx_buffer;
}
