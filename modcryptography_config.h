/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017-2019 Damiano Mazzella
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef MBEDTLS_USER_CONFIG_FILE_H
#define MBEDTLS_USER_CONFIG_FILE_H

#undef MBEDTLS_FS_IO
#undef MBEDTLS_NET_C
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_PKCS11_C
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_DTLS_BADMAC_LIMIT
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY 
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_NET_C
#undef MBEDTLS_POLY1305_C
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_RIPEMD160_C
#undef MBEDTLS_MD4_C
#undef MBEDTLS_HKDF_C
#undef MBEDTLS_VERSION_C
#undef MBEDTLS_VERSION_FEATURES
#undef MBEDTLS_XTEA_C
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_BLOWFISH_C
#undef MBEDTLS_ECJPAKE_C
#undef MBEDTLS_CTR_DRBG_C
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_CAMELLIA_C

/* CERTIFICATE RSA */
#undef MBEDTLS_RSA_C
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

#if defined(__thumb2__) || defined(__thumb__) || defined(__arm__)
#define MBEDTLS_NO_PLATFORM_ENTROPY

#if !defined(calloc) && !defined(free)
#include "py/gc.h"
#define gc_calloc(a, b) gc_alloc((a * b), 0)
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO gc_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO gc_free
#endif // !defined(calloc) && !defined(free)

#if defined(STM32WB)
#if defined(HAL_PKA_MODULE_ENABLED)
#undef MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_ALT
// // TODO:
// // controllare le funzioni mbedtls_ecdsa_sign e mbedtls_ecdsa_verify
// // #define MBEDTLS_ECDSA_VERIFY_ALT
// // #define MBEDTLS_ECDSA_SIGN_ALT

// #define MBEDTLS_ECP_DP_SECP192R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
// #define MBEDTLS_ECP_DP_SECP192K1_ENABLED
// #define MBEDTLS_ECP_DP_SECP224K1_ENABLED
// #define MBEDTLS_ECP_DP_SECP256K1_ENABLED
// #define MBEDTLS_ECP_DP_BP256R1_ENABLED
// #define MBEDTLS_ECP_DP_BP384R1_ENABLED
// #define MBEDTLS_ECP_DP_BP512R1_ENABLED
// #define MBEDTLS_ECP_DP_CURVE25519_ENABLED
// #define MBEDTLS_ECP_DP_CURVE448_ENABLED
#endif

#if defined(HAL_CRYP_MODULE_ENABLED)
#define MBEDTLS_GCM_ALT
#define MBEDTLS_AES_ALT
#endif
#endif

#endif // defined(__thumb2__) || defined(__thumb__) || defined(__arm__)

#endif // MBEDTLS_USER_CONFIG_FILE_H
