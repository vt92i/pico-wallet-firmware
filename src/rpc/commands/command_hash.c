#include "command_hash.h"

#include <stdio.h>

#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include "rpc/rpc.h"
#include "rpc/rpc_utils.h"

bool handle_md5(const rpc_payload_t* payload, rpc_buffer_t* response) {
  uint8_t md5_digest[16];

  if (mbedtls_md5_ret(payload->data, payload->data_len, md5_digest) != 0) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  rpc_build_response(response, RPC_STATUS_OK, md5_digest, sizeof(md5_digest));
  return true;
}

bool handle_sha256(const rpc_payload_t* payload, rpc_buffer_t* response) {
  uint8_t sha256_digest[32];

  if (mbedtls_sha256_ret(payload->data, payload->data_len, sha256_digest, 0) != 0) {
    rpc_build_response(response, RPC_STATUS_EXECUTION_ERROR, NULL, 0);
    return true;
  }

  rpc_build_response(response, RPC_STATUS_OK, sha256_digest, sizeof(sha256_digest));
  return true;
}
