/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017-2024 Damiano Mazzella
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

// Enable mbedtls modules.
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
// #define MBEDTLS_DES_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C

#if defined(__thumb2__) || defined(__thumb__) || defined(__arm__)
#define MBEDTLS_NO_PLATFORM_ENTROPY

#if defined(STM32WB)
#if defined(HAL_PKA_MODULE_ENABLED)
#undef MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_ALT
#define MBEDTLS_RSA_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDSA_SIGN_ALT
#endif

#if defined(HAL_CRYP_MODULE_ENABLED)
#define MBEDTLS_GCM_ALT
#define MBEDTLS_AES_ALT
#endif
#endif

#endif // defined(__thumb2__) || defined(__thumb__) || defined(__arm__)

#endif // MBEDTLS_USER_CONFIG_FILE_H
