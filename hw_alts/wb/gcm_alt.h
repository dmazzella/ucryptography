/**
 * \file gcm_alt.h.h
 *
 * \brief This file contains GCM definitions and functions.
 *
 * The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
 * in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 * (GCM), Natl. Inst. Stand. Technol.</em>
 *
 * For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
 * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 *
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  Copyright (C) 2019, STMicroelectronics, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file implements ST GCM HW services based on API from mbed TLS
 */
#ifndef MBEDTLS_GCM_ALT_H
#define MBEDTLS_GCM_ALT_H

#if defined(MBEDTLS_GCM_ALT)
#include "stm32wbxx_hal.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \brief          AES context structure
 *
 */
    typedef struct mbedtls_gcm_context
    {
        uint32_t gcm_key[8];          /* Encryption/Decryption key           */
        CRYP_HandleTypeDef hcryp_gcm; /* HW driver handle                    */
        uint32_t ctx_save_cr;         /* Saved HW context for multi-instance */
        uint64_t len;                 /* total length of the encrypted data. */
        int mode;                     /* The operation to perform:
                                               #MBEDTLS_GCM_ENCRYPT or
                                               #MBEDTLS_GCM_DECRYPT.             */
    } mbedtls_gcm_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_GCM_ALT */

#endif /* MBEDTLS_GCM_ALT_H */