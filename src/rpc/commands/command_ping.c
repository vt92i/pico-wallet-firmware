#include <stdio.h>

#include "rpc/rpc.h"
#include "rpc/rpc_utils.h"

bool handle_ping(const rpc_payload_t* payload, rpc_buffer_t* response) {
  (void)payload;

  rpc_build_response(response, RPC_STATUS_OK, NULL, 0);
  return true;
}
