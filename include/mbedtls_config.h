#ifndef _MBEDTLS_CONFIG_H
#define _MBEDTLS_CONFIG_H

#define MBEDTLS_PLATFORM_ZEROIZE_ALT /**< Use alternative implementation for zeroizing memory. */
#define MBEDTLS_MD_C                 /**< Enable generic message digest wrapper. */
#define MBEDTLS_PKCS5_C              /**< Enable PKCS#5 functions (e.g., PBKDF2). */
#define MBEDTLS_SHA512_C             /**< Enable SHA-512 cryptographic hash functions. */
#define MBEDTLS_SHA256_C             /**< Enable SHA-256 cryptographic hash functions. */
#define MBEDTLS_MD5_C                /**< Enable MD5 cryptographic hash functions. */

#endif /* _MBEDTLS_CONFIG_H */
