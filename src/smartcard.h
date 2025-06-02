#ifndef _SMARTCARD_H_
#define _SMARTCARD_H_

#include "bip39.h"
#include "stdint.h"

static void generate_entropy(uint8_t entropy_out[BIP39_ENTROPY_SIZE]);
void generate_mnemonic();

#endif /* _SMARTCARD_H_ */
