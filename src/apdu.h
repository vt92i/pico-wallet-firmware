#ifndef _APDU_H_
#define _APDU_H_

#include <stdbool.h>
#include <stdint.h>

#define APDU_CLA          0x80

#define APDU_HEADER_SIZE  4    // CLA, INS, P1, P2
#define APDU_MAX_DATA_LEN 255  // Maximum length of data field
#define APDU_MAX_RX_PACKET_SIZE \
  (APDU_HEADER_SIZE + 1 + APDU_MAX_DATA_LEN + 1)  // Maximum APDU packet size (CLA + INS + P1 + P2 + Lc + Data + Le)
#define APDU_MAX_TX_PACKET_SIZE (APDU_MAX_DATA_LEN + 2)  // Maximum APDU response size (Data + SW1 + SW2)

typedef enum {
  APDU_SW_OK = 0x9000,                   // Command executed successfully
  APDU_SW_WAITING = 0x6000,              // Processing is not done yet
  APDU_SW_CLASS_NOT_SUPPORTED = 0x6E00,  // Class not supported
  APDU_SW_INSTR_NOT_SUPPORTED = 0x6D00,  // Instruction not supported
  // APDU_SW_INCORRECT_P1_P2 = 0x6A86,      // Incorrect P1 or P2 parameters
  APDU_SW_WRONG_DATA = 0x6A80,    // Wrong data format
  APDU_SW_WRONG_LENGTH = 0x6700,  // Wrong length
} apdu_sw_t;

typedef struct {
  uint8_t* data;
  uint16_t data_len;
} apdu_buffer_t;

typedef struct {
  uint8_t cla;          // Class of the command
  uint8_t ins;          // Instruction code
  uint8_t p1;           // Parameter 1
  uint8_t p2;           // Parameter 2
  uint16_t lc;          // Length of the data field
  const uint8_t* data;  // Pointer to the data field (if any)
  uint8_t le;           // Expected length of the response (0 if not specified)
} apdu_packet_t;

bool apdu_parse(const apdu_buffer_t* apdu_buffer, apdu_packet_t* packet);
void apdu_build_response(apdu_buffer_t* apdu_buffer, apdu_sw_t status, const uint8_t* data, uint16_t data_len);
apdu_buffer_t apdu_handle(const apdu_buffer_t* apdu_buffer);

#endif /* _APDU_H_ */
