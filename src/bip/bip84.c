#include "bip/bip84.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha256.h"

#include "uECC.h"
#include "utils/base58.h"
#include "utils/segwit.h"

static const uint32_t HARDENED_OFFSET = 0x80000000;

static int ckd_priv(const uint8_t *k_par, const uint8_t *c_par, uint32_t index, uint8_t *k_child, uint8_t *c_child) {
  if (!k_par || !c_par || !k_child || !c_child) return 1;

  int ret = 1;
  uint8_t data[37] = {0};
  uint8_t I[64], IL[32], IR[32];

  mbedtls_mpi il_mpi, k_mpi, curve_order_mpi, k_child_mpi;
  mbedtls_ecp_group grp;

  mbedtls_mpi_init(&il_mpi);
  mbedtls_mpi_init(&k_mpi);
  mbedtls_mpi_init(&curve_order_mpi);
  mbedtls_mpi_init(&k_child_mpi);
  mbedtls_ecp_group_init(&grp);

  data[33] = (uint8_t)((index >> 24) & 0xFF);
  data[34] = (index >> 16) & 0xFF;
  data[35] = (index >> 8) & 0xFF;
  data[36] = index & 0xFF;

  if (index >= HARDENED_OFFSET) {
    data[0] = 0x00;
    memcpy(data + 1, k_par, 32);
  } else {
    uint8_t pubkey_uncompressed[65] = {0};
    uint8_t pubkey_compressed[33] = {0};

    if (uECC_compute_public_key(k_par, pubkey_uncompressed, uECC_secp256k1()) == 0) {
      ret = 1;
      goto cleanup;
    }
    uECC_compress(pubkey_uncompressed, pubkey_compressed, uECC_secp256k1());

    memcpy(data, pubkey_compressed, 33);
  }

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (md_info == NULL) {
    ret = 1;
    goto cleanup;
  }

  ret = mbedtls_md_hmac(md_info, c_par, 32, data, sizeof(data), I);
  if (ret != 0) goto cleanup;

  memcpy(IL, I, 32);
  memcpy(IR, I + 32, 32);

  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  if (ret != 0) goto cleanup;

  mbedtls_mpi_copy(&curve_order_mpi, &grp.N);

  ret = mbedtls_mpi_read_binary(&il_mpi, IL, 32);
  if (ret != 0) goto cleanup;
  ret = mbedtls_mpi_read_binary(&k_mpi, k_par, 32);
  if (ret != 0) goto cleanup;

  ret = mbedtls_mpi_add_mpi(&k_child_mpi, &il_mpi, &k_mpi);
  if (ret != 0) goto cleanup;
  ret = mbedtls_mpi_mod_mpi(&k_child_mpi, &k_child_mpi, &curve_order_mpi);
  if (ret != 0) goto cleanup;

  if (mbedtls_mpi_cmp_int(&k_child_mpi, 0) <= 0) {
    ret = 1;
    goto cleanup;
  }

  ret = mbedtls_mpi_write_binary(&k_child_mpi, k_child, 32);
  if (ret != 0) goto cleanup;

  memcpy(c_child, IR, 32);

  ret = 0;
  goto cleanup;

cleanup:
  mbedtls_mpi_free(&il_mpi);
  mbedtls_mpi_free(&k_mpi);
  mbedtls_mpi_free(&curve_order_mpi);
  mbedtls_mpi_free(&k_child_mpi);
  mbedtls_ecp_group_free(&grp);

  mbedtls_platform_zeroize(I, sizeof(I));
  mbedtls_platform_zeroize(IL, sizeof(IL));
  mbedtls_platform_zeroize(IR, sizeof(IR));
  mbedtls_platform_zeroize(data, sizeof(data));

  return ret;
}

static int P2WPKH_generate_witprog(const uint8_t *public_key, uint8_t *witprog) {
  if (!public_key || !witprog) return 1;

  uint8_t sha256_digest[32] = {0};
  int ret = mbedtls_sha256_ret(public_key, 33, sha256_digest, 0);
  if (ret != 0) return ret;

  ret = mbedtls_ripemd160_ret(sha256_digest, sizeof(sha256_digest), witprog);
  if (ret != 0) return ret;

  return 0;
}

bip84_status_t bip84_get_index_info(const char root_key[static BIP32_ROOT_KEY_SIZE], const uint32_t index,
                                    char address_out[static BIP84_ADDRESS_SIZE],
                                    uint8_t public_key_out[static BIP84_PUBLIC_KEY_SIZE],
                                    uint8_t private_key_out[static BIP84_PRIVATE_KEY_SIZE]) {
  uint8_t decoded_key[86] = {0};
  if (b58_decode(root_key, decoded_key, sizeof(decoded_key)) != 0) return BIP84_STATUS_ERR_BASE58;

  uint8_t chain_code[32], key_data[33], private_key[32];

  memcpy(chain_code, decoded_key + 13, 32);
  memcpy(key_data, decoded_key + 45, 33);
  if (key_data[0] != 0x00) return 0;
  memcpy(private_key, key_data + 1, 32);

  mbedtls_platform_zeroize(decoded_key, sizeof(decoded_key));
  mbedtls_platform_zeroize(key_data, sizeof(key_data));

  uint8_t child_private_key[32], child_chain_code[32];

  const uint8_t coin_type = 1;  // Bitcoin Testnet

  uint32_t path[] = {
      84 + HARDENED_OFFSET, coin_type + HARDENED_OFFSET, 0 + HARDENED_OFFSET, 0, index,
  };

  for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    ckd_priv(private_key, chain_code, path[i], child_private_key, child_chain_code);

    memcpy(private_key, child_private_key, 32);
    memcpy(chain_code, child_chain_code, 32);
  }

  uint8_t public_key_uncompressed[65] = {0};
  if (uECC_compute_public_key(private_key, public_key_uncompressed, uECC_secp256k1()) == 0) {
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    return BIP84_STATUS_ERR_UECC;
  }
  uint8_t public_key_compressed[33] = {0};
  uECC_compress(public_key_uncompressed, public_key_compressed, uECC_secp256k1());

  int witver = 0;
  uint8_t witprog[20] = {0};
  char *hrp = "tb";  // Testnet Human Readable Part

  if (P2WPKH_generate_witprog(public_key_compressed, witprog) != 0) {
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    return BIP84_STATUS_ERR_WITPROG;
  }

  if (segwit_address_encode(address_out, BIP84_ADDRESS_SIZE, hrp, witver, witprog, sizeof(witprog)) != 0) {
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    return BIP84_STATUS_ERR_SEGWIT_ENCODE;
  }

  memcpy(public_key_out, public_key_compressed, BIP84_PUBLIC_KEY_SIZE);
  memcpy(private_key_out, private_key, BIP84_PRIVATE_KEY_SIZE);

  mbedtls_platform_zeroize(private_key, sizeof(private_key));
  mbedtls_platform_zeroize(chain_code, sizeof(chain_code));
  mbedtls_platform_zeroize(child_private_key, sizeof(child_private_key));
  mbedtls_platform_zeroize(child_chain_code, sizeof(child_chain_code));
  mbedtls_platform_zeroize(public_key_uncompressed, sizeof(public_key_uncompressed));
  mbedtls_platform_zeroize(public_key_compressed, sizeof(public_key_compressed));

  return BIP84_STATUS_OK;
}
