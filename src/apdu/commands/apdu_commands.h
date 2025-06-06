#pragma once

typedef enum {
  APDU_INS_HASH_MD5 = 0xF4,
  APDU_INS_HASH_SHA256 = 0xF5,

  APDU_INS_INITIALIZE_WALLET = 0xA0,
  APDU_INS_RESET_WALLET = 0xA1,
} apdu_ins_t;
