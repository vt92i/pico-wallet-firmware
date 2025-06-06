#include "command_hash.h"

#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include "apdu_utils.h"

bool handle_md5(const apdu_packet_t* packet, apdu_buffer_t* response) {
  uint8_t md5_digest[16];

  if (mbedtls_md5_ret(packet->data, packet->lc, md5_digest) != 0) {
    apdu_build_response(response, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
    return false;
  }

  apdu_build_response(response, APDU_SW_OK, md5_digest, sizeof(md5_digest));
  return true;
}

bool handle_sha256(const apdu_packet_t* packet, apdu_buffer_t* response) {
  uint8_t sha256_digest[32];

  if (mbedtls_sha256_ret(packet->data, packet->lc, sha256_digest, 0) != 0) {
    apdu_build_response(response, APDU_SW_INSTR_NOT_SUPPORTED, NULL, 0);
    return false;
  }

  apdu_build_response(response, APDU_SW_OK, sha256_digest, sizeof(sha256_digest));
  return true;
}
