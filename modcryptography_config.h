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

// #undef MBEDTLS_RSA_C
// #undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
// #undef MBEDTLS_X509_RSASSA_PSS_SUPPORT
// #undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
// #undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
// #undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

#if defined(__thumb2__) || defined(__thumb__) || defined(__arm__)
#define MBEDTLS_NO_PLATFORM_ENTROPY

#if !defined(calloc) && !defined(free)
#include "py/gc.h"
#define gc_calloc(a, b) gc_alloc((a * b), 0)
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO gc_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO gc_free
#endif // !defined(calloc) && !defined(free)

#endif // defined(__thumb2__) || defined(__thumb__) || defined(__arm__)

#endif // MBEDTLS_USER_CONFIG_FILE_H
