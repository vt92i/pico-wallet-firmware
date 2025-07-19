#ifndef _MBEDTLS_CONFIG_H
#define _MBEDTLS_CONFIG_H

#define MBEDTLS_PLATFORM_ZEROIZE_C       /**< Enable platform-specific zeroization functions. */

#define MBEDTLS_BIGNUM_C                 /**< Enable big number (arbitrary precision integer) functions. */
#define MBEDTLS_ECP_C                    /**< Enable elliptic curve cryptography (ECP) functions. */
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED /**< Enable secp256k1 elliptic curve. */
#define MBEDTLS_CTR_DRBG_C               /**< Enable CTR_DRBG (Deterministic Random Bit Generator). */

#define MBEDTLS_MD_C                     /**< Enable generic message digest wrapper. */
#define MBEDTLS_AES_C                    /**< Enable AES (Advanced Encryption Standard) block cipher. */
#define MBEDTLS_CIPHER_C                 /**< Enable generic cipher wrapper. */
#define MBEDTLS_GCM_C                    /**< Enable Galois/Counter Mode (GCM) for authenticated encryption. */
#define MBEDTLS_PKCS5_C                  /**< Enable PKCS#5 functions (e.g., PBKDF2). */

#define MBEDTLS_RIPEMD160_C              /**< Enable RIPEMD-160 cryptographic hash functions. */
#define MBEDTLS_SHA512_C                 /**< Enable SHA-512 cryptographic hash functions. */
#define MBEDTLS_SHA256_C                 /**< Enable SHA-256 cryptographic hash functions. */
#define MBEDTLS_MD5_C                    /**< Enable MD5 cryptographic hash functions. */

#endif /* _MBEDTLS_CONFIG_H */
