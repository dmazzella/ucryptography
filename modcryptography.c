/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2026 Damiano Mazzella
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
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES of MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "py/runtime.h"
#include "py/mperrno.h"
#include "py/objtype.h"
#include "py/objstr.h"
#include "py/objint.h"
#if MICROPY_LONGINT_IMPL == MICROPY_LONGINT_IMPL_MPZ
#include "py/mpz.h"
#endif

// ucryptography feature toggles (MICROPY_PY_UCRYPTOGRAPHY_*).
#include "modcryptography_features.h"

#ifndef MBEDTLS_USER_CONFIG_FILE
#define MBEDTLS_USER_CONFIG_FILE "modcryptography_config.h"
#endif // MBEDTLS_USER_CONFIG_FILE

#if defined(__thumb2__) || defined(__thumb__) || defined(__arm__)
#if MICROPY_HW_ENABLE_RNG
#include "rng.h"
#define rand() rng_get()
#endif // MICROPY_HW_ENABLE_RNG
#endif

#if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_MPZ
#error "MICROPY_LONGINT_IMPL must be MICROPY_LONGINT_IMPL_MPZ"
#endif

MP_DEFINE_EXCEPTION(InvalidSignature, Exception);
MP_DEFINE_EXCEPTION(AlreadyFinalized, Exception);
MP_DEFINE_EXCEPTION(NotYetFinalized, Exception);
MP_DEFINE_EXCEPTION(UnsupportedAlgorithm, Exception);
MP_DEFINE_EXCEPTION(InvalidKey, Exception);
MP_DEFINE_EXCEPTION(InvalidToken, Exception);
MP_DEFINE_EXCEPTION(InvalidTag, Exception);

#define CHK_NE_GOTO(EC, ERR, LABEL) \
    if ((EC) != (ERR))              \
    {                               \
        goto LABEL;                 \
    }

#define CHK_EQ_GOTO(EC, ERR, LABEL) \
    if ((EC) == (ERR))              \
    {                               \
        goto LABEL;                 \
    }

static int mp_random(void *rng_state, byte *output, size_t len)
{
    size_t use_len;
    int rnd;

    (void)rng_state;

    while (len > 0)
    {
        use_len = len;
        if (use_len > sizeof(int))
            use_len = sizeof(int);
        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/rsa.h"
#include "rsa_alt_helpers.h"
#include "BLAKE2/ref/blake2.h"
#include "c25519/src/edsign.h"

struct _mp_ec_ecdsa_t;
struct _mp_ec_ecdh_t;
struct _mp_ec_curve_t;
struct _mp_ec_public_numbers_t;
struct _mp_ec_private_numbers_t;
struct _mp_ec_public_key_t;
struct _mp_ec_private_key_t;
struct _mp_ed25519_public_key_t;
struct _mp_ed25519_private_key_t;
struct _mp_rsa_public_numbers_t;
struct _mp_rsa_private_numbers_t;
struct _mp_rsa_public_key_t;
struct _mp_rsa_private_key_t;
struct _mp_hash_algorithm_t;
struct _mp_hash_context_t;
struct _mp_hmac_context_t;
struct _mp_x509_certificate_t;
struct _mp_x509_oid_t;
struct _mp_x509_name_attribute_t;
struct _mp_x509_name_t;
struct _mp_x509_general_name_t;
struct _mp_x509_san_t;
struct _mp_x509_basic_constraints_t;
struct _mp_x509_key_usage_t;
struct _mp_x509_ext_key_usage_t;
struct _mp_x509_ski_t;
struct _mp_x509_aki_t;
struct _mp_x509_unrecognized_extension_t;
struct _mp_x509_cert_builder_t;
struct _mp_x509_extension_t;
struct _mp_x509_extensions_t;
struct _mp_ciphers_aesgcm_t;
struct _mp_ciphers_cipher_t;
struct _mp_ciphers_cipher_encryptor_t;
struct _mp_ciphers_cipher_decryptor_t;
struct _mp_ciphers_algorithms_t;
struct _mp_ciphers_modes_cbc_t;
struct _mp_ciphers_modes_gcm_t;
struct _mp_util_prehashed_t;
struct _mp_padding_pkcs1v15_t;
struct _mp_padding_pss_t;
struct _mp_padding_oaep_t;
struct _mp_padding_mgf1_t;
struct _mp_twofactor_hotp_t;
struct _mp_twofactor_totp_t;

typedef struct _mp_ec_curve_t
{
    mp_obj_base_t base;
    mp_int_t ecp_group_id;
    mp_obj_t p;
    mp_obj_t a;
    mp_obj_t b;
    mp_obj_t n;
    mp_obj_t G_x;
    mp_obj_t G_y;
} mp_ec_curve_t;

typedef struct _mp_ec_public_numbers_t
{
    mp_obj_base_t base;
    struct _mp_ec_curve_t *curve;
    mp_obj_t x;
    mp_obj_t y;
    struct _mp_ec_public_key_t *public_key;
} mp_ec_public_numbers_t;

typedef struct _mp_ec_private_numbers_t
{
    mp_obj_base_t base;
    struct _mp_ec_public_numbers_t *public_numbers;
    mp_obj_t private_value;
    struct _mp_ec_private_key_t *private_key;
} mp_ec_private_numbers_t;

typedef struct _mp_ec_public_key_t
{
    mp_obj_base_t base;
    struct _mp_ec_public_numbers_t *public_numbers;
    mp_obj_t public_bytes;
} mp_ec_public_key_t;

typedef struct _mp_ec_private_key_t
{
    mp_obj_base_t base;
    struct _mp_ec_curve_t *curve;
    struct _mp_ec_private_numbers_t *private_numbers;
    struct _mp_ec_public_key_t *public_key;
    mp_obj_t private_bytes;
} mp_ec_private_key_t;

typedef struct _mp_ed25519_public_key_t
{
    mp_obj_base_t base;
    mp_obj_t public_bytes;
} mp_ed25519_public_key_t;

typedef struct _mp_ed25519_private_key_t
{
    mp_obj_base_t base;
    struct _mp_ed25519_public_key_t *public_key;
    mp_obj_t private_bytes;
} mp_ed25519_private_key_t;

typedef struct _mp_rsa_public_numbers_t
{
    mp_obj_base_t base;
    mp_obj_t e;
    mp_obj_t n;
    struct _mp_rsa_public_key_t *public_key;
} mp_rsa_public_numbers_t;

typedef struct _mp_rsa_private_numbers_t
{
    mp_obj_base_t base;
    mp_obj_t p;
    mp_obj_t q;
    mp_obj_t d;
    mp_obj_t dmp1;
    mp_obj_t dmq1;
    mp_obj_t iqmp;
    struct _mp_rsa_public_numbers_t *public_numbers;
    struct _mp_rsa_private_key_t *private_key;
} mp_rsa_private_numbers_t;

typedef struct _mp_rsa_public_key_t
{
    mp_obj_base_t base;
    struct _mp_rsa_public_numbers_t *public_numbers;
    mp_obj_t public_bytes;
} mp_rsa_public_key_t;

typedef struct _mp_rsa_private_key_t
{
    mp_obj_base_t base;
    struct _mp_rsa_private_numbers_t *private_numbers;
    struct _mp_rsa_public_key_t *public_key;
    mp_obj_t private_bytes;
} mp_rsa_private_key_t;

typedef struct _mp_hash_algorithm_t
{
    mp_obj_base_t base;
    mp_int_t md_type;
    mp_int_t digest_size;
} mp_hash_algorithm_t;

typedef struct _mp_hash_context_t
{
    mp_obj_base_t base;
    struct _mp_hash_algorithm_t *algorithm;
    vstr_t *data;
    bool finalized;
} mp_hash_context_t;

typedef struct _mp_hmac_context_t
{
    mp_obj_base_t base;
    vstr_t *key;
    vstr_t *data;
    struct _mp_hash_context_t *hash_context;
    bool finalized;
} mp_hmac_context_t;

typedef struct _mp_x509_certificate_t
{
    mp_obj_base_t base;
    mp_obj_t version;
    mp_obj_t serial_number;
    mp_obj_t not_valid_before;
    mp_obj_t not_valid_after;
    mp_obj_t subject;
    mp_obj_t issuer;
    mp_obj_t signature;
    mp_obj_t signature_algorithm_oid;
    struct _mp_hash_algorithm_t *signature_hash_algorithm;
    mp_obj_t extensions;
    mp_obj_t public_bytes;
    struct _mp_ec_public_key_t *ec_public_key;
    struct _mp_rsa_public_key_t *rsa_public_key;
    mp_obj_t tbs_certificate_bytes;
    mp_obj_t certificate_bytes;
} mp_x509_certificate_t;

typedef struct _mp_x509_oid_t
{
    mp_obj_base_t base;
    mp_obj_t dotted_string;
} mp_x509_oid_t;

typedef struct _mp_x509_name_attribute_t
{
    mp_obj_base_t base;
    mp_obj_t oid;
    mp_obj_t value;
} mp_x509_name_attribute_t;

typedef struct _mp_x509_name_t
{
    mp_obj_base_t base;
    mp_obj_t attributes;
} mp_x509_name_t;

typedef struct _mp_x509_general_name_t
{
    mp_obj_base_t base;
    mp_int_t kind; // GeneralName context tag: dNSName=2, iPAddress=7
    mp_obj_t value;
} mp_x509_general_name_t;

typedef struct _mp_x509_san_t
{
    mp_obj_base_t base;
    mp_obj_t general_names;
} mp_x509_san_t;

typedef struct _mp_x509_basic_constraints_t
{
    mp_obj_base_t base;
    bool ca;
    mp_obj_t path_length;
} mp_x509_basic_constraints_t;

typedef struct _mp_x509_key_usage_t
{
    mp_obj_base_t base;
    unsigned int flags;
} mp_x509_key_usage_t;

typedef struct _mp_x509_ext_key_usage_t
{
    mp_obj_base_t base;
    mp_obj_t usages;
} mp_x509_ext_key_usage_t;

typedef struct _mp_x509_ski_t
{
    mp_obj_base_t base;
    mp_obj_t digest;
} mp_x509_ski_t;

typedef struct _mp_x509_aki_t
{
    mp_obj_base_t base;
    mp_obj_t key_identifier;
} mp_x509_aki_t;

typedef struct _mp_x509_unrecognized_extension_t
{
    mp_obj_base_t base;
    mp_obj_t oid;
    mp_obj_t value;
} mp_x509_unrecognized_extension_t;

typedef struct _mp_x509_cert_builder_t
{
    mp_obj_base_t base;
    mp_obj_t subject_name;
    mp_obj_t issuer_name;
    mp_obj_t public_key;
    mp_obj_t serial_number;
    mp_obj_t not_valid_before;
    mp_obj_t not_valid_after;
    mp_obj_t extensions;
} mp_x509_cert_builder_t;

typedef struct _mp_x509_extension_t
{
    mp_obj_base_t base;
    mp_obj_t oid;
    mp_obj_t critical;
    mp_obj_t value;
} mp_x509_extension_t;

typedef struct _mp_x509_extensions_t
{
    mp_obj_base_t base;
    mp_obj_t list;
} mp_x509_extensions_t;

typedef struct _mp_x509_csr_t
{
    mp_obj_base_t base;
    mp_obj_t subject;
    mp_obj_t signature;
    mp_obj_t signature_algorithm_oid;
    struct _mp_hash_algorithm_t *signature_hash_algorithm;
    mp_obj_t extensions;
    mp_obj_t public_bytes;
    struct _mp_ec_public_key_t *ec_public_key;
    struct _mp_rsa_public_key_t *rsa_public_key;
    mp_obj_t tbs_certrequest_bytes;
    mp_obj_t is_signature_valid;
} mp_x509_csr_t;

typedef struct _mp_x509_csr_ext_ctx_t
{
    mp_obj_t list;
} mp_x509_csr_ext_ctx_t;

typedef struct _mp_x509_csr_builder_t
{
    mp_obj_base_t base;
    mp_obj_t subject_name;
    mp_obj_t extensions;
} mp_x509_csr_builder_t;

typedef struct _mp_best_available_encryption_t
{
    mp_obj_base_t base;
    mp_obj_t password;
} mp_best_available_encryption_t;

typedef struct _mp_ciphers_aesgcm_t
{
    mp_obj_base_t base;
    vstr_t *key;
} mp_ciphers_aesgcm_t;

typedef struct _mp_ciphers_algorithms_t
{
    mp_obj_base_t base;
    vstr_t *key;
    mp_int_t type;
} mp_ciphers_algorithms_t;

typedef struct _mp_ciphers_modes_cbc_t
{
    mp_obj_base_t base;
    vstr_t *initialization_vector;
} mp_ciphers_modes_cbc_t;

typedef struct _mp_ciphers_modes_gcm_t
{
    mp_obj_base_t base;
    vstr_t *initialization_vector;
    vstr_t *tag;
    mp_int_t min_tag_length;
    bool has_tag;
} mp_ciphers_modes_gcm_t;

typedef struct _mp_ciphers_modes_ecb_t
{
    mp_obj_base_t base;
} mp_ciphers_modes_ecb_t;

typedef struct _mp_ciphers_cipher_t
{
    mp_obj_base_t base;
    struct _mp_ciphers_algorithms_t *algorithm;
    mp_obj_t mode;
    mp_int_t mode_type;
    struct _mp_ciphers_cipher_encryptor_t *encryptor;
    struct _mp_ciphers_cipher_decryptor_t *decryptor;
} mp_ciphers_cipher_t;

typedef struct _mp_ciphers_cipher_encryptor_t
{
    mp_obj_base_t base;
    struct _mp_ciphers_cipher_t *cipher;
    vstr_t *data;
    vstr_t *aadata;
    bool finalized;
} mp_ciphers_cipher_encryptor_t;

typedef struct _mp_ciphers_cipher_decryptor_t
{
    mp_obj_base_t base;
    struct _mp_ciphers_cipher_t *cipher;
    vstr_t *data;
    vstr_t *aadata;
    bool finalized;
} mp_ciphers_cipher_decryptor_t;

typedef struct _mp_ec_ecdh_t
{
    mp_obj_base_t base;
} mp_ec_ecdh_t;

typedef struct _mp_ec_ecdsa_t
{
    mp_obj_base_t base;
    struct _mp_hash_algorithm_t *algorithm;
} mp_ec_ecdsa_t;

typedef struct _mp_util_prehashed_t
{
    mp_obj_base_t base;
    struct _mp_hash_algorithm_t *algorithm;
} mp_util_prehashed_t;

typedef struct _mp_util_rfc6979_t
{
    mp_obj_base_t base;
    mp_obj_t msg;
    mp_obj_t x;
    mp_obj_t q;
    mp_int_t qlen;
    mp_int_t rlen;
    struct _mp_hash_algorithm_t *algorithm;
} mp_util_rfc6979_t;

typedef struct _mp_padding_pkcs1v15_t
{
    mp_obj_base_t base;
    mp_obj_t name;
} mp_padding_pkcs1v15_t;

typedef struct _mp_padding_pss_t
{
    mp_obj_base_t base;
    mp_obj_t name;
    struct _mp_padding_mgf1_t *mgf;
    mp_int_t salt_length;
    mp_int_t max_length;
} mp_padding_pss_t;

typedef struct _mp_padding_oaep_t
{
    mp_obj_base_t base;
    mp_obj_t name;
    struct _mp_padding_mgf1_t *mgf;
    struct _mp_hash_algorithm_t *algorithm;
    mp_obj_t label;
} mp_padding_oaep_t;

typedef struct _mp_padding_mgf1_t
{
    mp_obj_base_t base;
    struct _mp_hash_algorithm_t *algorithm;
} mp_padding_mgf1_t;

typedef struct _mp_twofactor_hotp_t
{
    mp_obj_base_t base;
    mp_obj_t key;
    mp_int_t length;
    struct _mp_hash_algorithm_t *algorithm;
    bool enforce_key_length;
} mp_twofactor_hotp_t;

typedef struct _mp_twofactor_totp_t
{
    mp_obj_base_t base;
    mp_obj_t key;
    mp_int_t length;
    struct _mp_hash_algorithm_t *algorithm;
    mp_int_t time_step;
    bool enforce_key_length;
} mp_twofactor_totp_t;

enum
{
    CIPHER_ALGORITHM_AES = 1,
#ifdef MBEDTLS_DES_C
    CIPHER_ALGORITHM_3DES = 2,
#endif
};

enum
{
    CIPHER_MODE_CBC = 1,
    CIPHER_MODE_GCM = 2,
    CIPHER_MODE_ECB = 3,
};

enum
{
    SERIALIZATION_ENCODING_DER = 1,
    SERIALIZATION_ENCODING_PEM = 2,
    SERIALIZATION_ENCODING_X962 = 3,
};

enum
{
    MBEDTLS_MD_NONE_BLAKE2S = -1,
};

// constants for block protocol ioctl
#define BLOCKDEV_IOCTL_INIT (1)
#define BLOCKDEV_IOCTL_DEINIT (2)
#define BLOCKDEV_IOCTL_SYNC (3)
#define BLOCKDEV_IOCTL_BLOCK_COUNT (4)
#define BLOCKDEV_IOCTL_BLOCK_SIZE (5)
#define BLOCKDEV_IOCTL_BLOCK_ERASE (6)

static const mp_obj_type_t ec_ecdsa_type;
static const mp_obj_type_t ec_ecdh_type;
static const mp_obj_type_t ec_curve_secp256r1_type;
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
static const mp_obj_type_t ec_curve_secp384r1_type;
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
static const mp_obj_type_t ec_curve_secp521r1_type;
#endif
static const mp_obj_type_t ec_public_numbers_type;
static const mp_obj_type_t ec_private_numbers_type;
static const mp_obj_type_t ec_public_key_type;
static const mp_obj_type_t ec_private_key_type;
static const mp_obj_type_t ed25519_private_key_type;
static const mp_obj_type_t ed25519_public_key_type;
static const mp_obj_type_t rsa_public_numbers_type;
static const mp_obj_type_t rsa_private_numbers_type;
static const mp_obj_type_t rsa_public_key_type;
static const mp_obj_type_t rsa_private_key_type;
static const mp_obj_type_t hash_algorithm_sha1_type;
static const mp_obj_type_t hash_algorithm_sha256_type;
static const mp_obj_type_t hash_algorithm_sha384_type;
static const mp_obj_type_t hash_algorithm_sha512_type;
static const mp_obj_type_t hash_algorithm_blake2s_type;
static const mp_obj_type_t hash_algorithm_prehashed_type;
static const mp_obj_type_t hash_context_type;
static const mp_obj_type_t hmac_context_type;
static const mp_obj_type_t x509_certificate_type;
static const mp_obj_type_t x509_oid_type;
static const mp_obj_type_t x509_name_attribute_type;
static const mp_obj_type_t x509_name_type;
static const mp_obj_type_t x509_dns_name_type;
static const mp_obj_type_t x509_ip_address_type;
static const mp_obj_type_t x509_san_type;
static const mp_obj_type_t x509_basic_constraints_type;
static const mp_obj_type_t x509_key_usage_type;
static const mp_obj_type_t x509_ext_key_usage_type;
static const mp_obj_type_t x509_ski_type;
static const mp_obj_type_t x509_aki_type;
static const mp_obj_type_t x509_unrecognized_extension_type;
static const mp_obj_type_t x509_cert_builder_type;
#if MICROPY_PY_UCRYPTOGRAPHY_X509
static const mp_obj_type_t x509_extension_type;
static const mp_obj_type_t x509_extensions_type;
#endif
static const mp_obj_type_t ciphers_aesgcm_type;
static const mp_obj_type_t ciphers_cipher_type;
static const mp_obj_type_t ciphers_cipher_encryptor_type;
static const mp_obj_type_t ciphers_cipher_decryptor_type;
static const mp_obj_type_t ciphers_algorithms_aes_type;
static const mp_obj_type_t ciphers_algorithms_3des_type;
static const mp_obj_type_t ciphers_modes_cbc_type;
static const mp_obj_type_t ciphers_modes_gcm_type;
static const mp_obj_type_t ciphers_modes_ecb_type;
static const mp_obj_type_t padding_pkcs1v15_type;
static const mp_obj_type_t padding_pss_type;
static const mp_obj_type_t padding_oaep_type;
#if MICROPY_PY_UCRYPTOGRAPHY_MGF1
static const mp_obj_type_t padding_mgf1_type;
#endif
static const mp_obj_type_t twofactor_hotp_type;
static const mp_obj_type_t twofactor_totp_type;

#ifdef STM32WB
#if defined(MBEDTLS_GCM_ALT) || defined(MBEDTLS_AES_ALT)
void HAL_CRYP_MspInit(CRYP_HandleTypeDef *hcryp)
{
    if (hcryp->Instance == AES1)
    {
        __HAL_RCC_AES1_CLK_ENABLE();
    }
    else if (hcryp->Instance == AES2)
    {
        __HAL_RCC_AES2_CLK_ENABLE();
    }
}

void HAL_CRYP_MspDeInit(CRYP_HandleTypeDef *hcryp)
{
    if (hcryp->Instance == AES1)
    {
        __HAL_RCC_AES1_FORCE_RESET();
        __HAL_RCC_AES1_RELEASE_RESET();
        __HAL_RCC_AES1_CLK_DISABLE();
    }
    else if (hcryp->Instance == AES2)
    {
        __HAL_RCC_AES2_FORCE_RESET();
        __HAL_RCC_AES2_RELEASE_RESET();
        __HAL_RCC_AES2_CLK_DISABLE();
    }
}
#endif

#ifdef MBEDTLS_ECP_ALT
void HAL_PKA_MspInit(PKA_HandleTypeDef *hpka)
{
    if (hpka->Instance == PKA)
    {
        __HAL_RCC_PKA_CLK_ENABLE();
    }
}

void HAL_PKA_MspDeInit(PKA_HandleTypeDef *hpka)
{
    if (hpka->Instance == PKA)
    {
        __HAL_RCC_PKA_FORCE_RESET();
        __HAL_RCC_PKA_RELEASE_RESET();
        __HAL_RCC_PKA_CLK_DISABLE();
    }
}
#endif
#endif

static mpz_t *mp_mpz_for_int(mp_obj_t arg, mpz_t *temp)
{
    if (mp_obj_is_small_int(arg))
    {
        mpz_init_from_int(temp, MP_OBJ_SMALL_INT_VALUE(arg));
        return temp;
    }
    else
    {
        mp_obj_int_t *arp_p = MP_OBJ_TO_PTR(arg);
        return &(arp_p->mpz);
    }
}

static vstr_t *vstr_new_from_mpz(const mpz_t *i)
{
    size_t len = mp_int_format_size(mpz_max_num_bits(i), 10, NULL, '\0');
    vstr_t *vstr = vstr_new(len);
    size_t fmt_len = mpz_as_str_inpl(i, 10, NULL, 'a', '\0', vstr_str(vstr));
    vstr_cut_tail_bytes(vstr, len - fmt_len);
    vstr->len = fmt_len;
    return vstr;
}

static mp_obj_t int_bit_length(mp_obj_t x)
{
    mpz_t n_temp;
    mpz_t *n = mp_mpz_for_int(x, &n_temp);
    if (mpz_is_zero(n))
    {
        return mp_obj_new_int_from_uint(0);
    }
    mpz_t *dest = m_new_obj(mpz_t);
    dest->neg = n->neg;
    dest->fixed_dig = 0;
    dest->alloc = n->alloc;
    dest->len = n->len;
    dest->dig = m_new(mpz_dig_t, n->alloc);
    memcpy(dest->dig, n->dig, n->alloc * sizeof(mpz_dig_t));
    mpz_abs_inpl(dest, dest);
    mp_uint_t num_bits = 0;
    while (dest->len > 0)
    {
        mpz_shr_inpl(dest, dest, 1);
        num_bits++;
    }
    if (dest != NULL)
    {
        m_del(mpz_dig_t, dest->dig, dest->alloc);
        m_del_obj(mpz_t, dest);
    }
    if (n == &n_temp)
    {
        mpz_deinit(n);
    }
    return mp_obj_new_int_from_ull(num_bits);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_int_bit_length_obj, int_bit_length);

static mp_obj_t cryptography_small_to_big_int(mp_obj_t arg)
{
    if (!mp_obj_is_int(arg))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("int required, got %s"), mp_obj_get_type_str(arg)));
    }

    if (mp_obj_is_small_int(arg))
    {
        mp_obj_int_t *o = mp_obj_int_new_mpz();
        mpz_init_from_int(&o->mpz, MP_OBJ_SMALL_INT_VALUE(arg));
        return MP_OBJ_FROM_PTR(o);
    }

    return arg;
}

static void cryptography_get_buffer(const mp_obj_t o, bool big_endian, mp_buffer_info_t *bufinfo)
{
    mp_obj_t oo = o;
    if (mp_obj_is_int(oo))
    {
        mpz_t o_temp;
        mpz_t *o_temp_p = mp_mpz_for_int(o, &o_temp);
        bool is_neg = mpz_is_neg(o_temp_p);
        if (is_neg)
        {
            mpz_abs_inpl(o_temp_p, o_temp_p);
        }
        vstr_t vstr;
        vstr_init_len(&vstr, (mp_obj_get_int(int_bit_length(oo)) + 7) / 8);
        mpz_as_bytes(o_temp_p, big_endian, is_neg, vstr.len, (byte *)vstr.buf);
        if (is_neg)
        {
            mpz_neg_inpl(o_temp_p, o_temp_p);
        }
        if (o_temp_p == &o_temp)
        {
            mpz_deinit(o_temp_p);
        }

        oo = mp_obj_new_bytes((byte *)vstr.buf, vstr.len);
        vstr_clear(&vstr);
    }

    if (!mp_get_buffer(oo, bufinfo, MP_BUFFER_READ))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("object with buffer protocol or int required, got %s"), mp_obj_get_type_str(oo)));
    }
}

static void mbedtls_mpi_read_binary_from_mp_obj(mbedtls_mpi *mpi, const mp_obj_t o, bool big_endian)
{
    mp_buffer_info_t bufinfo_o;
    cryptography_get_buffer(o, big_endian, &bufinfo_o);

    if (big_endian)
    {
        mbedtls_mpi_read_binary(mpi, (const byte *)bufinfo_o.buf, bufinfo_o.len);
    }
    else
    {
        mbedtls_mpi_read_binary_le(mpi, (const byte *)bufinfo_o.buf, bufinfo_o.len);
    }
}

static mp_obj_t mbedtls_mpi_write_binary_to_mp_obj(const mbedtls_mpi *mpi, bool big_endian)
{
    vstr_t vstr_mpi;
    vstr_init_len(&vstr_mpi, mbedtls_mpi_size(mpi));
    if (big_endian)
    {
        mbedtls_mpi_write_binary(mpi, (byte *)vstr_mpi.buf, vstr_mpi.len);
    }
    else
    {
        mbedtls_mpi_write_binary_le(mpi, (byte *)vstr_mpi.buf, vstr_mpi.len);
    }
    mp_obj_t oo = mp_obj_int_from_bytes_impl(big_endian, vstr_mpi.len, (const byte *)vstr_mpi.buf);
    vstr_clear(&vstr_mpi);
    return oo;
}

static uint8_t constant_time_bytes_eq(uint8_t *a, size_t len_a, uint8_t *b, size_t len_b)
{
    size_t i = 0;
    uint8_t mismatch = 0;
    if (len_a != len_b)
    {
        return 0;
    }
    for (i = 0; i < len_a; i++)
    {
        mismatch |= a[i] ^ b[i];
    }
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    return (mismatch & 1) == 0;
}

static mp_obj_t mod_constant_time_bytes_eq(mp_obj_t a, mp_obj_t b)
{
    mp_buffer_info_t bufinfo_a;
    mp_get_buffer_raise(a, &bufinfo_a, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_b;
    mp_get_buffer_raise(b, &bufinfo_b, MP_BUFFER_READ);

    return mp_obj_new_bool(constant_time_bytes_eq(bufinfo_a.buf, bufinfo_a.len, bufinfo_b.buf, bufinfo_b.len));
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_constant_time_bytes_eq_obj, mod_constant_time_bytes_eq);

// Validate the hash algorithm object and compute the message digest into
// out_digest (raw copy for None/Prehashed). Returns the resolved hash algorithm
// (NULL for None). Raises UnsupportedAlgorithm if the object is not supported.
static mp_hash_algorithm_t *cryptography_hash_digest(mp_obj_t algorithm, const mp_buffer_info_t *bufinfo_data, vstr_t *out_digest)
{
    if (!mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm or None"));
    }

    mp_hash_algorithm_t *hash_algorithm = NULL;
    if (mp_obj_get_type(algorithm) == &mp_type_NoneType)
    {
        vstr_init_len(out_digest, 0);
        vstr_add_strn(out_digest, (const char *)bufinfo_data->buf, bufinfo_data->len);
    }
    else if (mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        hash_algorithm = (mp_hash_algorithm_t *)((mp_util_prehashed_t *)MP_OBJ_TO_PTR(algorithm))->algorithm;
        vstr_init_len(out_digest, 0);
        vstr_add_strn(out_digest, (const char *)bufinfo_data->buf, bufinfo_data->len);
    }
    else
    {
        hash_algorithm = MP_OBJ_TO_PTR(algorithm);
        vstr_init_len(out_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(hash_algorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(hash_algorithm->md_type), (const byte *)bufinfo_data->buf, bufinfo_data->len, (byte *)out_digest->buf);
    }
    return hash_algorithm;
}

static int util_decode_dss_signature(const unsigned char *sig, size_t slen, mbedtls_mpi *r, mbedtls_mpi *s)
{
    int ret;
    unsigned char *p = (unsigned char *)sig;
    const unsigned char *end = sig + slen;
    size_t len;
    if (sig == NULL)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p + len != end)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, r)) != 0 || (ret = mbedtls_asn1_get_mpi(&p, end, s)) != 0)
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p != end)
    {
        ret = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;
    }

cleanup:

    return (ret);
}

static mp_obj_t mod_decode_dss_signature(mp_obj_t signature_obj)
{
    mp_buffer_info_t bufinfo_signature;
    mp_get_buffer_raise(signature_obj, &bufinfo_signature, MP_BUFFER_READ);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_mpi s;
    mbedtls_mpi_init(&s);

    util_decode_dss_signature(bufinfo_signature.buf, bufinfo_signature.len, &r, &s);

    mp_obj_t rs[2] = {mbedtls_mpi_write_binary_to_mp_obj(&r, true), mbedtls_mpi_write_binary_to_mp_obj(&s, true)};

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return mp_obj_new_tuple(2, rs);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_decode_dss_signature_obj, mod_decode_dss_signature);

static int util_encode_dss_signature(const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *sig, size_t *slen)
{
    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, (const byte *)buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, (const byte *)buf, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    memcpy(sig, p, len);
    *slen = len;

    return (0);
}

static mp_obj_t mod_encode_dss_signature(mp_obj_t r_obj, mp_obj_t s_obj)
{
    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_read_binary_from_mp_obj(&r, r_obj, true);

    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary_from_mp_obj(&s, s_obj, true);

    vstr_t vstr_sig;
    vstr_init_len(&vstr_sig, MBEDTLS_ECDSA_MAX_LEN);

    size_t size_sig = 0;
    int res = util_encode_dss_signature(&r, &s, (byte *)vstr_sig.buf, &size_sig);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (res != 0)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("signature malformed"));
    }

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_sig.buf, size_sig);
    vstr_clear(&vstr_sig);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_encode_dss_signature_obj, mod_encode_dss_signature);

static mp_obj_t ec_ecdsa_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, true);
    enum
    {
        ARG_hash_algorithm
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_hash_algorithm, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}}};
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t hash_algorithm = args[ARG_hash_algorithm].u_obj;
    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(hash_algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm or None"));
    }

    mp_ec_ecdsa_t *ECDSA = m_new_obj(mp_ec_ecdsa_t);
    ECDSA->base.type = &ec_ecdsa_type;
    ECDSA->algorithm = hash_algorithm;
    return MP_OBJ_FROM_PTR(ECDSA);
}

static void ec_ecdsa_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_ecdsa_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_algorithm || attr == MP_QSTR__algorithm)
            {
                dest[0] = self->algorithm;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t ec_ecdsa_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_algorithm), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR__algorithm), MP_ROM_PTR(mp_const_none)},
};

static MP_DEFINE_CONST_DICT(ec_ecdsa_locals_dict, ec_ecdsa_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_ecdsa_type,
    MP_QSTR_ECDSA,
    MP_TYPE_FLAG_NONE,
    make_new, ec_ecdsa_make_new,
    attr, ec_ecdsa_attr,
    locals_dict, &ec_ecdsa_locals_dict);

static mp_obj_t ec_ecdh_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 1, true);
    mp_ec_ecdh_t *ECDH = m_new_obj(mp_ec_ecdh_t);
    ECDH->base.type = &ec_ecdh_type;
    return MP_OBJ_FROM_PTR(ECDH);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_ecdh_type,
    MP_QSTR_ECDH,
    MP_TYPE_FLAG_NONE,
    make_new, ec_ecdh_make_new);

static mp_obj_t ec_parse_keypair(const mbedtls_ecp_keypair *ecp_keypair, bool private)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_EC
    (void)ecp_keypair;
    (void)private;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ec disabled (enable MICROPY_PY_UCRYPTOGRAPHY_EC)"));
#else
    mp_ec_curve_t *EllipticCurve = m_new_obj(mp_ec_curve_t);
    switch (ecp_keypair->private_grp.id)
    {
    case MBEDTLS_ECP_DP_SECP256R1:
    {
        EllipticCurve->base.type = &ec_curve_secp256r1_type;
        break;
    }
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    case MBEDTLS_ECP_DP_SECP384R1:
    {
        EllipticCurve->base.type = &ec_curve_secp384r1_type;
        break;
    }
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    case MBEDTLS_ECP_DP_SECP521R1:
    {
        EllipticCurve->base.type = &ec_curve_secp521r1_type;
        break;
    }
#endif
    default:
    {
        break;
    }
    }

    EllipticCurve->ecp_group_id = ecp_keypair->private_grp.id;

    mp_ec_public_key_t *EllipticCurvePublicKey = m_new_obj(mp_ec_public_key_t);
    EllipticCurvePublicKey->base.type = &ec_public_key_type;

    mp_ec_public_numbers_t *EllipticCurvePublicNumbers = m_new_obj(mp_ec_public_numbers_t);
    EllipticCurvePublicNumbers->base.type = &ec_public_numbers_type;
    EllipticCurvePublicNumbers->curve = EllipticCurve;
    EllipticCurvePublicNumbers->x = mbedtls_mpi_write_binary_to_mp_obj(&ecp_keypair->private_Q.private_X, true);
    EllipticCurvePublicNumbers->y = mbedtls_mpi_write_binary_to_mp_obj(&ecp_keypair->private_Q.private_Y, true);
    EllipticCurvePublicNumbers->public_key = EllipticCurvePublicKey;

    mp_obj_t s2b_x = EllipticCurvePublicNumbers->x;
    int x_len = (mp_obj_get_int(int_bit_length(s2b_x)) + 7) / 8;

    mp_obj_t s2b_y = EllipticCurvePublicNumbers->y;
    int y_len = (mp_obj_get_int(int_bit_length(s2b_y)) + 7) / 8;

    int n_size = mbedtls_mpi_size(&ecp_keypair->private_grp.N);
    int pksize = (n_size * 2);
    vstr_t vstr_public_bytes;
    vstr_init_len(&vstr_public_bytes, pksize);
    vstr_ins_byte(&vstr_public_bytes, 0, 0x04);
    mp_obj_int_to_bytes(s2b_x, x_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len), true, false, false);
    mp_obj_int_to_bytes(s2b_y, y_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len) + (n_size - y_len) + x_len, true, false, false);

    EllipticCurvePublicKey->public_numbers = EllipticCurvePublicNumbers;
    EllipticCurvePublicKey->public_bytes = mp_obj_new_bytes((const byte *)vstr_public_bytes.buf, vstr_public_bytes.len);
    vstr_clear(&vstr_public_bytes);

    vstr_t vstr_private_bytes;
    vstr_init_len(&vstr_private_bytes, mbedtls_mpi_size(&ecp_keypair->private_d));
    mbedtls_mpi_write_binary(&ecp_keypair->private_d, (byte *)vstr_private_bytes.buf, vstr_private_bytes.len);

    mp_ec_private_numbers_t *EllipticCurvePrivateNumbers = m_new_obj(mp_ec_private_numbers_t);
    EllipticCurvePrivateNumbers->base.type = &ec_private_numbers_type;
    EllipticCurvePrivateNumbers->private_value = mp_obj_int_from_bytes_impl(true, vstr_private_bytes.len, (const byte *)vstr_private_bytes.buf);
    EllipticCurvePrivateNumbers->public_numbers = EllipticCurvePublicNumbers;

    mp_ec_private_key_t *EllipticCurvePrivateKey = m_new_obj(mp_ec_private_key_t);
    EllipticCurvePrivateKey->base.type = &ec_private_key_type;
    EllipticCurvePrivateKey->curve = EllipticCurve;
    EllipticCurvePrivateKey->private_numbers = EllipticCurvePrivateNumbers;
    EllipticCurvePrivateKey->public_key = EllipticCurvePublicKey;
    EllipticCurvePrivateKey->private_bytes = mp_obj_new_bytes((const byte *)vstr_private_bytes.buf, vstr_private_bytes.len);
    vstr_clear(&vstr_private_bytes);

    EllipticCurvePrivateNumbers->private_key = EllipticCurvePrivateKey;

    if (private)
    {
        return EllipticCurvePrivateKey;
    }
    else
    {
        return EllipticCurvePublicKey;
    }
#endif
}

static const mp_obj_type_t best_available_encryption_type;

// OpenSSL legacy KDF (EVP_BytesToKey with MD5, one iteration) for the traditional
// "DEK-Info" encrypted PEM; the salt is the first 8 bytes of the IV.
static void serialization_bytes_to_key_md5(const byte *pw, size_t pwlen, const byte *salt8, byte *out, size_t outlen)
{
    const mbedtls_md_info_t *md5 = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md5, 0);
    byte d[16];
    size_t have = 0;
    bool first = true;
    while (have < outlen)
    {
        mbedtls_md_starts(&ctx);
        if (!first)
        {
            mbedtls_md_update(&ctx, d, sizeof(d));
        }
        mbedtls_md_update(&ctx, pw, pwlen);
        mbedtls_md_update(&ctx, salt8, 8);
        mbedtls_md_finish(&ctx, d);
        size_t n = (outlen - have < sizeof(d)) ? (outlen - have) : sizeof(d);
        memcpy(out + have, d, n);
        have += n;
        first = false;
    }
    mbedtls_md_free(&ctx);
}

// Encrypt a traditional (SEC1/PKCS#1) private-key DER into an OpenSSL
// "Proc-Type: 4,ENCRYPTED / DEK-Info: AES-256-CBC" PEM. Round-trips with the
// module's password-aware loaders and with openssl/PyCA.
static mp_obj_t serialization_encrypt_trad_pem(mp_obj_t der_obj, const char *label, mp_obj_t password_obj)
{
    mp_buffer_info_t der, pw;
    mp_get_buffer_raise(der_obj, &der, MP_BUFFER_READ);
    mp_get_buffer_raise(password_obj, &pw, MP_BUFFER_READ);
    if (pw.len == 0)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Password cannot be empty"));
    }

    byte iv[16];
    mp_random(NULL, iv, sizeof(iv));
    byte key[32];
    serialization_bytes_to_key_md5((const byte *)pw.buf, pw.len, iv, key, sizeof(key));

    size_t pad = 16 - (der.len % 16);
    size_t ct_len = der.len + pad;
    byte *pt = m_new(byte, ct_len);
    memcpy(pt, der.buf, der.len);
    memset(pt + der.len, (byte)pad, pad);
    byte *ct = m_new(byte, ct_len);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    byte iv2[16];
    memcpy(iv2, iv, sizeof(iv2));
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, ct_len, iv2, pt, ct);
    mbedtls_aes_free(&aes);
    m_del(byte, pt, ct_len);
    if (ret != 0)
    {
        m_del(byte, ct, ct_len);
        mp_raise_ValueError(MP_ERROR_TEXT("Key encryption failed"));
    }

    size_t b64_need = 0;
    mbedtls_base64_encode(NULL, 0, &b64_need, ct, ct_len);
    byte *b64 = m_new(byte, b64_need);
    size_t b64_len = 0;
    mbedtls_base64_encode(b64, b64_need, &b64_len, ct, ct_len);
    m_del(byte, ct, ct_len);

    vstr_t v;
    vstr_init(&v, 512);
    vstr_printf(&v, "-----BEGIN %s-----\n", label);
    vstr_printf(&v, "Proc-Type: 4,ENCRYPTED\n");
    vstr_printf(&v, "DEK-Info: AES-256-CBC,");
    for (size_t i = 0; i < sizeof(iv); i++)
    {
        vstr_printf(&v, "%02X", iv[i]);
    }
    vstr_printf(&v, "\n\n");
    for (size_t i = 0; i < b64_len; i += 64)
    {
        size_t n = (b64_len - i < 64) ? (b64_len - i) : 64;
        vstr_add_strn(&v, (const char *)(b64 + i), n);
        vstr_add_byte(&v, '\n');
    }
    vstr_printf(&v, "-----END %s-----\n", label);
    m_del(byte, b64, b64_need);

    mp_obj_t out = mp_obj_new_bytes((const byte *)v.buf, v.len);
    vstr_clear(&v);
    return out;
}

static mp_obj_t ec_key_dumps(mp_obj_t public_o, mp_obj_t private_o, mp_obj_t encoding_o, int ecp_group_id)
{
    if (!mp_obj_is_int(encoding_o))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected encoding int"));
    }
    mp_int_t encoding = mp_obj_get_int(encoding_o);
    if (encoding != SERIALIZATION_ENCODING_DER && encoding != SERIALIZATION_ENCODING_PEM && encoding != SERIALIZATION_ENCODING_X962)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Expected encoding value 1 (DER), 2 (PEM) or 3 (X962)"));
    }

    vstr_t vstr_out;
    vstr_init_len(&vstr_out, 4096);
    int ret = 0;
    mp_obj_t oo = mp_const_none;

    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(public_o, &bufinfo_public_bytes, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_private_bytes;
    bool dump_private_key = mp_get_buffer(private_o, &bufinfo_private_bytes, MP_BUFFER_READ);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk);
    mbedtls_ecp_keypair_init(ecp);
    mbedtls_ecp_group_load(&ecp->private_grp, ecp_group_id);
    mbedtls_ecp_point_read_binary(&ecp->private_grp, &ecp->private_Q, (const byte *)bufinfo_public_bytes.buf, bufinfo_public_bytes.len);

    if (dump_private_key)
    {
        mbedtls_mpi_read_binary(&ecp->private_d, (const byte *)bufinfo_private_bytes.buf, bufinfo_private_bytes.len);
        if (encoding == SERIALIZATION_ENCODING_DER && (ret = mbedtls_pk_write_key_der(&pk, (byte *)vstr_out.buf, vstr_out.len)) > 0)
        {
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)(vstr_out.buf + vstr_out.len - ret), ret);
            vstr_clear(&vstr_out);
        }
        else if (encoding == SERIALIZATION_ENCODING_PEM && (ret = mbedtls_pk_write_key_pem(&pk, (byte *)vstr_out.buf, vstr_out.len)) == 0)
        {
            ret = strlen((char *)vstr_out.buf);
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)vstr_out.buf, ret);
            vstr_clear(&vstr_out);
        }
    }
    else
    {
        if (encoding == SERIALIZATION_ENCODING_DER && (ret = mbedtls_pk_write_pubkey_der(&pk, (byte *)vstr_out.buf, vstr_out.len)) > 0)
        {
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)(vstr_out.buf + vstr_out.len - ret), ret);
            vstr_clear(&vstr_out);
        }
        else if (encoding == SERIALIZATION_ENCODING_PEM && (ret = mbedtls_pk_write_pubkey_pem(&pk, (byte *)vstr_out.buf, vstr_out.len)) == 0)
        {
            ret = strlen((char *)vstr_out.buf);
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)vstr_out.buf, ret);
            vstr_clear(&vstr_out);
        }
        else if (encoding == SERIALIZATION_ENCODING_X962)
        {
            vstr_clear(&vstr_out);
            if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY)
            {
                mbedtls_pk_free(&pk);
                mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("ec public key"));
            }
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)bufinfo_public_bytes.buf, bufinfo_public_bytes.len);
        }
    }
    return oo;
}

static void ec_curve_secpXXXr1_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_curve_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_p)
            {
                dest[0] = self->p;
                return;
            }
            if (attr == MP_QSTR_a)
            {
                dest[0] = self->a;
                return;
            }
            if (attr == MP_QSTR_b)
            {
                dest[0] = self->b;
                return;
            }
            if (attr == MP_QSTR_n)
            {
                dest[0] = self->n;
                return;
            }
            if (attr == MP_QSTR_G_x)
            {
                dest[0] = self->G_x;
                return;
            }
            if (attr == MP_QSTR_G_y)
            {
                dest[0] = self->G_y;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static mp_ec_curve_t *ec_curve_secpXXXr1_make_new_helper(const mp_obj_type_t *type, mbedtls_ecp_group_id group_id)
{
    mp_ec_curve_t *EllipticCurve = m_new_obj(mp_ec_curve_t);
    EllipticCurve->base.type = type;
    EllipticCurve->ecp_group_id = group_id;

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, EllipticCurve->ecp_group_id);

    EllipticCurve->p = mbedtls_mpi_write_binary_to_mp_obj(&grp.P, true);
    EllipticCurve->a = mp_obj_new_int(-3);
    EllipticCurve->b = mbedtls_mpi_write_binary_to_mp_obj(&grp.B, true);
    EllipticCurve->n = mbedtls_mpi_write_binary_to_mp_obj(&grp.N, true);
    EllipticCurve->G_x = mbedtls_mpi_write_binary_to_mp_obj(&grp.G.private_X, true);
    EllipticCurve->G_y = mbedtls_mpi_write_binary_to_mp_obj(&grp.G.private_Y, true);

    mbedtls_ecp_group_free(&grp);

    return EllipticCurve;
}

static mp_obj_t ec_curve_secp256r1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 1, true);
    mp_ec_curve_t *EllipticCurve = ec_curve_secpXXXr1_make_new_helper(&ec_curve_secp256r1_type, MBEDTLS_ECP_DP_SECP256R1);
    return MP_OBJ_FROM_PTR(EllipticCurve);
}

static const mp_rom_map_elem_t ec_curve_secp256r1_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_secp256r1)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(256)},
    {MP_ROM_QSTR(MP_QSTR_p), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_a), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_b), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_n), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_x), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_y), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(ec_curve_secp256r1_locals_dict, ec_curve_secp256r1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_curve_secp256r1_type,
    MP_QSTR_SECP256R1,
    MP_TYPE_FLAG_NONE,
    make_new, ec_curve_secp256r1_make_new,
    attr, ec_curve_secpXXXr1_attr,
    locals_dict, &ec_curve_secp256r1_locals_dict);

#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
static mp_obj_t ec_curve_secp384r1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 1, true);
    mp_ec_curve_t *EllipticCurve = ec_curve_secpXXXr1_make_new_helper(&ec_curve_secp384r1_type, MBEDTLS_ECP_DP_SECP384R1);
    return MP_OBJ_FROM_PTR(EllipticCurve);
}

static const mp_rom_map_elem_t ec_curve_secp384r1_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_secp384r1)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(384)},
    {MP_ROM_QSTR(MP_QSTR_p), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_a), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_b), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_n), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_x), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_y), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(ec_curve_secp384r1_locals_dict, ec_curve_secp384r1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_curve_secp384r1_type,
    MP_QSTR_SECP384R1,
    MP_TYPE_FLAG_NONE,
    make_new, ec_curve_secp384r1_make_new,
    attr, ec_curve_secpXXXr1_attr,
    locals_dict, &ec_curve_secp384r1_locals_dict);

#endif

#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
static mp_obj_t ec_curve_secp521r1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 1, true);
    mp_ec_curve_t *EllipticCurve = ec_curve_secpXXXr1_make_new_helper(&ec_curve_secp521r1_type, MBEDTLS_ECP_DP_SECP521R1);
    return MP_OBJ_FROM_PTR(EllipticCurve);
}

static const mp_rom_map_elem_t ec_curve_secp521r1_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_secp521r1)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(521)},
    {MP_ROM_QSTR(MP_QSTR_p), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_a), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_b), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_n), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_x), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_G_y), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(ec_curve_secp521r1_locals_dict, ec_curve_secp521r1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_curve_secp521r1_type,
    MP_QSTR_SECP521R1,
    MP_TYPE_FLAG_NONE,
    make_new, ec_curve_secp521r1_make_new,
    attr, ec_curve_secpXXXr1_attr,
    locals_dict, &ec_curve_secp521r1_locals_dict);

#endif

static mp_obj_t ec_public_numbers_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_EC
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ec disabled (enable MICROPY_PY_UCRYPTOGRAPHY_EC)"));
#else
    mp_arg_check_num(n_args, n_kw, 3, 3, true);
    mp_obj_t x = args[0];
    mp_obj_t y = args[1];
    mp_ec_curve_t *EllipticCurve = MP_OBJ_TO_PTR(args[2]);
    if (!mp_obj_is_int(x))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected X int"));
    }
    if (!mp_obj_is_int(y))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Y int"));
    }
    if (
        !mp_obj_is_type(EllipticCurve, &ec_curve_secp256r1_type)
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp384r1_type)
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp521r1_type)
#endif
    )
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec curve"));
    }

    mp_obj_t s2b_x = cryptography_small_to_big_int(x);
    int x_len = (mp_obj_get_int(int_bit_length(s2b_x)) + 7) / 8;

    mp_obj_t s2b_y = cryptography_small_to_big_int(y);
    int y_len = (mp_obj_get_int(int_bit_length(s2b_y)) + 7) / 8;

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, EllipticCurve->ecp_group_id);
    int n_size = mbedtls_mpi_size(&grp.N);
    mbedtls_ecp_group_free(&grp);

    int pksize = (n_size * 2);
    vstr_t vstr_public_bytes;
    vstr_init_len(&vstr_public_bytes, pksize);
    vstr_ins_byte(&vstr_public_bytes, 0, 0x04);
    mp_obj_int_to_bytes(s2b_x, x_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len), true, false, false);
    mp_obj_int_to_bytes(s2b_y, y_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len) + (n_size - y_len) + x_len, true, false, false);

    mp_ec_public_numbers_t *EllipticCurvePublicNumbers = m_new_obj(mp_ec_public_numbers_t);
    EllipticCurvePublicNumbers->base.type = &ec_public_numbers_type;
    EllipticCurvePublicNumbers->curve = EllipticCurve;
    EllipticCurvePublicNumbers->x = x;
    EllipticCurvePublicNumbers->y = y;

    mp_ec_public_key_t *EllipticCurvePublicKey = m_new_obj(mp_ec_public_key_t);
    EllipticCurvePublicKey->base.type = &ec_public_key_type;
    EllipticCurvePublicKey->public_bytes = mp_obj_new_bytes((const byte *)vstr_public_bytes.buf, vstr_public_bytes.len);
    EllipticCurvePublicKey->public_numbers = EllipticCurvePublicNumbers;

    EllipticCurvePublicNumbers->public_key = EllipticCurvePublicKey;
    vstr_clear(&vstr_public_bytes);

    return MP_OBJ_FROM_PTR(EllipticCurvePublicNumbers);
#endif
}

static mp_obj_t ec_public_numbers_public_key(mp_obj_t obj)
{
    mp_ec_public_numbers_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_numbers_public_key_obj, ec_public_numbers_public_key);

static void ec_public_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_public_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_curve)
            {
                dest[0] = self->curve;
                return;
            }
            if (attr == MP_QSTR_x)
            {
                dest[0] = self->x;
                return;
            }
            if (attr == MP_QSTR_y)
            {
                dest[0] = self->y;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t ec_public_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_x), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_y), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_ec_public_numbers_public_key_obj)},
};

static MP_DEFINE_CONST_DICT(ec_public_numbers_locals_dict, ec_public_numbers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_public_numbers_type,
    MP_QSTR_EllipticCurvePublicNumbers,
    MP_TYPE_FLAG_NONE,
    make_new, ec_public_numbers_make_new,
    attr, ec_public_numbers_attr,
    locals_dict, &ec_public_numbers_locals_dict);

static mp_obj_t ec_private_numbers_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_EC
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ec disabled (enable MICROPY_PY_UCRYPTOGRAPHY_EC)"));
#else
    mp_arg_check_num(n_args, n_kw, 2, 2, true);
    mp_obj_t private_value = args[0];
    mp_ec_public_numbers_t *EllipticCurvePublicNumbers = MP_OBJ_TO_PTR(args[1]);
    if (!mp_obj_is_int(private_value))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected private_value int"));
    }
    if (!mp_obj_is_type(EllipticCurvePublicNumbers, &ec_public_numbers_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec.EllipticCurvePublicNumbers"));
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, EllipticCurvePublicNumbers->curve->ecp_group_id);
    int pksize = mbedtls_mpi_size(&grp.N);
    mbedtls_ecp_group_free(&grp);

    vstr_t vstr_private_bytes;
    vstr_init_len(&vstr_private_bytes, pksize);
    mp_obj_int_to_bytes(cryptography_small_to_big_int(private_value), pksize, (byte *)vstr_private_bytes.buf, true, false, false);

    mp_ec_private_numbers_t *EllipticCurvePrivateNumbers = m_new_obj(mp_ec_private_numbers_t);
    EllipticCurvePrivateNumbers->base.type = &ec_private_numbers_type;
    EllipticCurvePrivateNumbers->private_value = private_value;
    EllipticCurvePrivateNumbers->public_numbers = EllipticCurvePublicNumbers;

    mp_ec_private_key_t *EllipticCurvePrivateKey = m_new_obj(mp_ec_private_key_t);
    EllipticCurvePrivateKey->base.type = &ec_private_key_type;
    EllipticCurvePrivateKey->curve = EllipticCurvePublicNumbers->curve;
    EllipticCurvePrivateKey->public_key = EllipticCurvePublicNumbers->public_key;
    EllipticCurvePrivateKey->private_bytes = mp_obj_new_bytes((const byte *)vstr_private_bytes.buf, vstr_private_bytes.len);
    EllipticCurvePrivateKey->private_numbers = EllipticCurvePrivateNumbers;

    EllipticCurvePrivateNumbers->private_key = EllipticCurvePrivateKey;
    vstr_clear(&vstr_private_bytes);

    return MP_OBJ_FROM_PTR(EllipticCurvePrivateNumbers);
#endif
}

static mp_obj_t ec_private_numbers_private_key(mp_obj_t obj)
{
    mp_ec_private_numbers_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_private_numbers_private_key_obj, ec_private_numbers_private_key);

static void ec_private_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_private_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_private_value)
            {
                dest[0] = self->private_value;
                return;
            }
            if (attr == MP_QSTR_public_numbers)
            {
                dest[0] = self->public_numbers;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t ec_private_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_private_value), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_private_key), MP_ROM_PTR(&mod_ec_private_numbers_private_key_obj)},
};

static MP_DEFINE_CONST_DICT(ec_private_numbers_locals_dict, ec_private_numbers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_private_numbers_type,
    MP_QSTR_EllipticCurvePrivateNumbers,
    MP_TYPE_FLAG_NONE,
    make_new, ec_private_numbers_make_new,
    attr, ec_private_numbers_attr,
    locals_dict, &ec_private_numbers_locals_dict);

static mp_obj_t ec_verify(size_t n_args, const mp_obj_t *args)
{
    mp_obj_t obj = args[0];
    mp_obj_t signature = args[1];
    mp_obj_t data = args[2];
    mp_obj_t ecdsa_obj = args[3];

    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    mp_buffer_info_t bufinfo_signature;
    mp_get_buffer_raise(signature, &bufinfo_signature, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (!mp_obj_is_type(ecdsa_obj, &ec_ecdsa_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec.ECDSA"));
    }

    mp_ec_ecdsa_t *ecdsa = MP_OBJ_TO_PTR(ecdsa_obj);
    vstr_t vstr_digest;
    cryptography_hash_digest(ecdsa->algorithm, &bufinfo_data, &vstr_digest);

    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(self->public_bytes, &bufinfo_public_bytes, MP_BUFFER_READ);

    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init(&ecp);
    mbedtls_ecp_group_load(&ecp.private_grp, self->public_numbers->curve->ecp_group_id);
    mbedtls_ecp_point_read_binary(&ecp.private_grp, &ecp.private_Q, (const byte *)bufinfo_public_bytes.buf, bufinfo_public_bytes.len);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_mpi s;
    mbedtls_mpi_init(&s);

    util_decode_dss_signature(bufinfo_signature.buf, bufinfo_signature.len, &r, &s);

    int ecdsa_verify = mbedtls_ecdsa_verify(&ecp.private_grp, (const byte *)vstr_digest.buf, vstr_digest.len, &ecp.private_Q, &r, &s);

    mbedtls_ecp_keypair_free(&ecp);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    vstr_clear(&vstr_digest);

    if (ecdsa_verify != 0)
    {
        mp_raise_msg_varg(&mp_type_InvalidSignature, MP_ERROR_TEXT("%d"), ecdsa_verify);
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ec_verify_obj, 4, 4, ec_verify);

static mp_obj_t ec_public_numbers(mp_obj_t obj)
{
    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_numbers;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_numbers_obj, ec_public_numbers);

static mp_obj_t ec_public_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_ec_public_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;

    (void)format;

    return ec_key_dumps(self->public_bytes, mp_const_none, encoding, self->public_numbers->curve->ecp_group_id);
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_ec_public_bytes_obj, 1, ec_public_bytes);

static void ec_public_key_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_curve)
            {
                dest[0] = self->public_numbers->curve;
                return;
            }
            if (attr == MP_QSTR_key_size)
            {
                mbedtls_ecp_group grp;
                mbedtls_ecp_group_init(&grp);
                mbedtls_ecp_group_load(&grp, self->public_numbers->curve->ecp_group_id);
                dest[0] = mp_obj_new_int(grp.nbits);
                mbedtls_ecp_group_free(&grp);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static mp_obj_t ec_from_encoded_point(mp_obj_t curve, mp_obj_t public_o)
{
    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(public_o, &bufinfo_public_bytes, MP_BUFFER_READ);

    mp_ec_curve_t *EllipticCurve = MP_OBJ_TO_PTR(curve);
    if (!mp_obj_is_type(EllipticCurve, &ec_curve_secp256r1_type)
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp384r1_type)
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp521r1_type)
#endif
    )
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec curve"));
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk);
    mbedtls_ecp_keypair_init(ecp);
    mbedtls_ecp_group_load(&ecp->private_grp, EllipticCurve->ecp_group_id);
    mbedtls_ecp_point_read_binary(&ecp->private_grp, &ecp->private_Q, (const byte *)bufinfo_public_bytes.buf, bufinfo_public_bytes.len);

    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY)
    {
        mp_obj_t pub_key = ec_parse_keypair(mbedtls_pk_ec(pk), false);
        mbedtls_pk_free(&pk);
        return pub_key;
    }
    else
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("public key"));
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_ec_from_encoded_point_obj, ec_from_encoded_point);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ec_from_encoded_point_obj, MP_ROM_PTR(&mod_ec_from_encoded_point_obj));

static const mp_rom_map_elem_t ec_public_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_from_encoded_point), MP_OBJ_FROM_PTR(&mod_static_ec_from_encoded_point_obj)},
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(&mod_ec_public_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_ec_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_OBJ_FROM_PTR(&mod_ec_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(ec_public_key_locals_dict, ec_public_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_public_key_type,
    MP_QSTR_EllipticCurvePublicKey,
    MP_TYPE_FLAG_NONE,
    attr, ec_public_key_attr,
    locals_dict, &ec_public_key_locals_dict);

static mp_obj_t ec_private_numbers(mp_obj_t obj)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_numbers;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_private_numbers_obj, ec_private_numbers);

static mp_obj_t ec_sign(mp_obj_t obj, mp_obj_t data, mp_obj_t ecdsa_obj)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif

    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (!mp_obj_is_type(ecdsa_obj, &ec_ecdsa_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec.ECDSA"));
    }

    mp_ec_ecdsa_t *ecdsa = MP_OBJ_TO_PTR(ecdsa_obj);
    vstr_t vstr_digest;
    cryptography_hash_digest(ecdsa->algorithm, &bufinfo_data, &vstr_digest);

    mp_buffer_info_t bufinfo_private_bytes;
    mp_get_buffer_raise(self->private_bytes, &bufinfo_private_bytes, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(self->public_key->public_bytes, &bufinfo_public_bytes, MP_BUFFER_READ);

    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init(&ecp);
    mbedtls_ecp_group_load(&ecp.private_grp, self->curve->ecp_group_id);
    mbedtls_ecp_point_read_binary(&ecp.private_grp, &ecp.private_Q, (const byte *)bufinfo_public_bytes.buf, bufinfo_public_bytes.len);
    mbedtls_mpi_read_binary(&ecp.private_d, (const byte *)bufinfo_private_bytes.buf, bufinfo_private_bytes.len);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_mpi s;
    mbedtls_mpi_init(&s);

    vstr_t vstr_signature;
    vstr_init_len(&vstr_signature, MBEDTLS_ECDSA_MAX_LEN);
    int ecdsa_sign = mbedtls_ecdsa_sign(&ecp.private_grp, &r, &s, &ecp.private_d, (const byte *)vstr_digest.buf, vstr_digest.len, mp_random, NULL);
    if (ecdsa_sign != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        vstr_clear(&vstr_digest);
        vstr_clear(&vstr_signature);
        mp_raise_msg_varg(&mp_type_InvalidSignature, MP_ERROR_TEXT("%d"), ecdsa_sign);
    }

    mbedtls_ecp_keypair_free(&ecp);

    util_encode_dss_signature(&r, &s, (byte *)vstr_signature.buf, &vstr_signature.len);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    vstr_clear(&vstr_digest);

    return mp_obj_new_bytes((const byte *)vstr_signature.buf, vstr_signature.len);
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_ec_sign_obj, ec_sign);

static mp_obj_t ec_public_key(mp_obj_t obj)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_key_obj, ec_public_key);

static mp_obj_t ec_private_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
        ARG_encryption_algorithm,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encryption_algorithm, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_ec_private_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;
    mp_obj_t encryption_algorithm = vals[ARG_encryption_algorithm].u_obj;

    (void)format;

    if (mp_obj_is_type(encryption_algorithm, &best_available_encryption_type))
    {
        if (!mp_obj_is_int(encoding) || mp_obj_get_int(encoding) != SERIALIZATION_ENCODING_PEM)
        {
            mp_raise_ValueError(MP_ERROR_TEXT("Encrypted private keys require PEM encoding"));
        }
        mp_obj_t der = ec_key_dumps(self->public_key->public_bytes, self->private_bytes, mp_obj_new_int(SERIALIZATION_ENCODING_DER), self->public_key->public_numbers->curve->ecp_group_id);
        return serialization_encrypt_trad_pem(der, "EC PRIVATE KEY", ((mp_best_available_encryption_t *)MP_OBJ_TO_PTR(encryption_algorithm))->password);
    }

    return ec_key_dumps(self->public_key->public_bytes, self->private_bytes, encoding, self->public_key->public_numbers->curve->ecp_group_id);
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_ec_private_bytes_obj, 1, ec_private_bytes);

static mp_obj_t ec_exchange(size_t n_args, const mp_obj_t *args)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_obj_t peer_public_key_o = (n_args == 2 ? args[1] : args[2]);

    if (n_args == 3 && !mp_obj_is_type(args[1], &ec_ecdh_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec.ECDH"));
    }

    if (!mp_obj_is_type(peer_public_key_o, &ec_public_key_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec.EllipticCurvePublicKey"));
    }

    mp_buffer_info_t bufinfo_private_bytes;
    mp_get_buffer_raise(self->private_bytes, &bufinfo_private_bytes, MP_BUFFER_READ);

    mp_ec_public_key_t *peer_public_key = MP_OBJ_TO_PTR(peer_public_key_o);

    mp_buffer_info_t bufinfo_peer_public_bytes;
    mp_get_buffer_raise(peer_public_key->public_bytes, &bufinfo_peer_public_bytes, MP_BUFFER_READ);

    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init(&ecp);
    mbedtls_ecp_group_load(&ecp.private_grp, self->public_key->public_numbers->curve->ecp_group_id);
    mbedtls_mpi_read_binary(&ecp.private_d, (const byte *)bufinfo_private_bytes.buf, bufinfo_private_bytes.len);

    mbedtls_ecp_point peer_Q;
    mbedtls_ecp_point_init(&peer_Q);
    mbedtls_ecp_point_read_binary(&ecp.private_grp, &peer_Q, (const byte *)bufinfo_peer_public_bytes.buf, bufinfo_peer_public_bytes.len);

    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    mbedtls_ecdh_compute_shared(&ecp.private_grp, &z, &peer_Q, &ecp.private_d, mp_random, NULL);

    vstr_t vstr_z_bytes;
    vstr_init_len(&vstr_z_bytes, mbedtls_mpi_size(&z));
    mbedtls_mpi_write_binary(&z, (byte *)vstr_z_bytes.buf, vstr_z_bytes.len);

    mbedtls_ecp_keypair_free(&ecp);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&peer_Q);
    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_z_bytes.buf, vstr_z_bytes.len);
    vstr_clear(&vstr_z_bytes);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ec_exchange_obj, 2, 3, ec_exchange);

static void ec_private_key_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_curve)
            {
                dest[0] = self->public_key->public_numbers->curve;
                return;
            }
            if (attr == MP_QSTR_key_size)
            {
                mbedtls_ecp_group grp;
                mbedtls_ecp_group_init(&grp);
                mbedtls_ecp_group_load(&grp, self->public_key->public_numbers->curve->ecp_group_id);
                dest[0] = mp_obj_new_int(grp.nbits);
                mbedtls_ecp_group_free(&grp);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t ec_private_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_private_numbers), MP_ROM_PTR(&mod_ec_private_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mod_ec_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_private_bytes), MP_ROM_PTR(&mod_ec_private_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_ec_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_exchange), MP_ROM_PTR(&mod_ec_exchange_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(ec_private_key_locals_dict, ec_private_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_private_key_type,
    MP_QSTR_EllipticCurvePrivateKey,
    MP_TYPE_FLAG_NONE,
    attr, ec_private_key_attr,
    locals_dict, &ec_private_key_locals_dict);

#if !defined(MBEDTLS_RSA_ALT)

static int rsa_pka_modexp(mbedtls_rsa_context *ctx,
                          int is_private,
                          const unsigned char *input,
                          unsigned char *output)
{
    int ret = 0;

    size_t mlen = mbedtls_mpi_size(&ctx->private_N);

    mbedtls_mpi A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_read_binary(&A, (const byte *)input, mlen);

    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    if ((ret = mbedtls_mpi_exp_mod(&X, &A, (is_private) ? &ctx->private_D : &ctx->private_E, &ctx->private_N, NULL)) == 0)
    {
        mbedtls_mpi_write_binary(&X, (byte *)output, mlen);
    }

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);
    return ret;
}

#endif /* MBEDTLS_RSA_ALT */

static mp_obj_t rsa_key_dumps(mp_rsa_public_numbers_t *public_numbers, mp_rsa_private_numbers_t *private_numbers, mp_obj_t encoding_o)
{
    if (!mp_obj_is_int(encoding_o))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected encoding int"));
    }
    mp_int_t encoding = mp_obj_get_int(encoding_o);
    if (encoding != SERIALIZATION_ENCODING_DER && encoding != SERIALIZATION_ENCODING_PEM)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Expected encoding value 1 (DER) or 2 (PEM)"));
    }

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, public_numbers->e, true);

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, public_numbers->n, true);

    mp_obj_t oo = mp_const_none;
    if (public_numbers != MP_OBJ_NULL && private_numbers == MP_OBJ_NULL)
    {
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

        int ret = 1;
        if ((ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E)) != 0)
        {
            mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_import"));
        }

        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        vstr_t vstr_out;
        vstr_init_len(&vstr_out, mp_obj_get_int(int_bit_length(public_numbers->n)) * 2);
        if (encoding == SERIALIZATION_ENCODING_DER && (ret = mbedtls_pk_write_pubkey_der(&pk, (byte *)vstr_out.buf, vstr_out.len)) > 0)
        {
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)(vstr_out.buf + vstr_out.len - ret), ret);
        }
        else if (encoding == SERIALIZATION_ENCODING_PEM && (ret = mbedtls_pk_write_pubkey_pem(&pk, (byte *)vstr_out.buf, vstr_out.len)) == 0)
        {
            ret = strlen((char *)vstr_out.buf);
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)vstr_out.buf, ret);
        }
        vstr_clear(&vstr_out);
    }
    else if (public_numbers != MP_OBJ_NULL && private_numbers != MP_OBJ_NULL)
    {
        mbedtls_mpi P;
        mbedtls_mpi_init(&P);
        mbedtls_mpi_read_binary_from_mp_obj(&P, private_numbers->p, true);

        mbedtls_mpi Q;
        mbedtls_mpi_init(&Q);
        mbedtls_mpi_read_binary_from_mp_obj(&Q, private_numbers->q, true);

        mbedtls_mpi D;
        mbedtls_mpi_init(&D);
        mbedtls_mpi_read_binary_from_mp_obj(&D, private_numbers->d, true);

        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

        int ret = 1;
        if ((ret = mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E)) != 0)
        {
            mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_import"));
        }

        if ((ret = mbedtls_rsa_complete(rsa)) != 0)
        {
            mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_complete"));
        }

        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        mbedtls_mpi_free(&P);
        mbedtls_mpi_free(&Q);
        mbedtls_mpi_free(&D);

        vstr_t vstr_out;
        vstr_init_len(&vstr_out, mp_obj_get_int(int_bit_length(public_numbers->n)) * 2);
        if (encoding == SERIALIZATION_ENCODING_DER && (ret = mbedtls_pk_write_key_der(&pk, (byte *)vstr_out.buf, vstr_out.len)) > 0)
        {
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)(vstr_out.buf + vstr_out.len - ret), ret);
        }
        else if (encoding == SERIALIZATION_ENCODING_PEM && (ret = mbedtls_pk_write_key_pem(&pk, (byte *)vstr_out.buf, vstr_out.len)) == 0)
        {
            ret = strlen((char *)vstr_out.buf);
            mbedtls_pk_free(&pk);
            oo = mp_obj_new_bytes((const byte *)vstr_out.buf, ret);
        }
        vstr_clear(&vstr_out);
    }

    return oo;
}

static mp_obj_t rsa_parse_keypair(const mbedtls_rsa_context *rsa, bool private)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_RSA
    (void)rsa;
    (void)private;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("rsa disabled (enable MICROPY_PY_UCRYPTOGRAPHY_RSA)"));
#else
    mp_rsa_public_numbers_t *RSAPublicNumbers = m_new_obj(mp_rsa_public_numbers_t);
    RSAPublicNumbers->base.type = &rsa_public_numbers_type;
    RSAPublicNumbers->e = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_E, true);
    RSAPublicNumbers->n = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_N, true);

    mp_rsa_public_key_t *RSAPublicKey = m_new_obj(mp_rsa_public_key_t);
    RSAPublicKey->base.type = &rsa_public_key_type;
    RSAPublicKey->public_bytes = rsa_key_dumps(RSAPublicNumbers, MP_OBJ_NULL, mp_obj_new_int(SERIALIZATION_ENCODING_DER));
    RSAPublicKey->public_numbers = RSAPublicNumbers;

    RSAPublicNumbers->public_key = RSAPublicKey;

    if (private)
    {
        mp_rsa_private_numbers_t *RSAPrivateNumbers = m_new_obj(mp_rsa_private_numbers_t);
        RSAPrivateNumbers->base.type = &rsa_private_numbers_type;
        RSAPrivateNumbers->public_numbers = RSAPublicNumbers;
        RSAPrivateNumbers->p = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_P, true);
        RSAPrivateNumbers->q = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_Q, true);
        RSAPrivateNumbers->d = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_D, true);
        RSAPrivateNumbers->dmp1 = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_DP, true);
        RSAPrivateNumbers->dmq1 = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_DQ, true);
        RSAPrivateNumbers->iqmp = mbedtls_mpi_write_binary_to_mp_obj(&rsa->private_QP, true);

        mp_rsa_private_key_t *RSAPrivateKey = m_new_obj(mp_rsa_private_key_t);
        RSAPrivateKey->base.type = &rsa_private_key_type;
        RSAPrivateKey->private_bytes = rsa_key_dumps(RSAPublicNumbers->public_key->public_numbers, RSAPrivateNumbers, mp_obj_new_int(SERIALIZATION_ENCODING_DER));
        RSAPrivateKey->private_numbers = RSAPrivateNumbers;
        RSAPrivateKey->public_key = RSAPublicNumbers->public_key;

        RSAPrivateNumbers->private_key = RSAPrivateKey;

        return MP_OBJ_FROM_PTR(RSAPrivateKey);
    }
    else
    {
        return MP_OBJ_FROM_PTR(RSAPublicKey);
    }

    return mp_const_none;
#endif
}

static void hash_algorithm_prehashed_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_util_prehashed_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_digest_size || attr == MP_QSTR__digest_size)
            {
                dest[0] = mp_obj_new_int(mbedtls_md_get_size(mbedtls_md_info_from_type(self->algorithm->md_type)));
                return;
            }
            if (attr == MP_QSTR__algorithm)
            {
                dest[0] = self->algorithm;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t hash_algorithm_prehashed_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR__algorithm), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR__digest_size), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_prehashed_locals_dict, hash_algorithm_prehashed_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_prehashed_type,
    MP_QSTR_Prehashed,
    MP_TYPE_FLAG_NONE,
    attr, hash_algorithm_prehashed_attr,
    locals_dict, &hash_algorithm_prehashed_locals_dict);

static mp_obj_t mod_hash_algorithm_prehashed(mp_obj_t hash_algorithm)
{
    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_blake2s_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    mp_util_prehashed_t *Prehashed = m_new_obj(mp_util_prehashed_t);
    Prehashed->base.type = &hash_algorithm_prehashed_type;
    Prehashed->algorithm = hash_algorithm;

    return MP_OBJ_FROM_PTR(Prehashed);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hash_algorithm_prehashed_obj, mod_hash_algorithm_prehashed);

static mp_obj_t hash_algorithm_sha1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_SHA1
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("sha1 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_SHA1)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha1_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA1;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
#endif
}

static const mp_rom_map_elem_t hash_algorithm_sha1_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_sha1)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(20)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_sha1_locals_dict, hash_algorithm_sha1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_sha1_type,
    MP_QSTR_SHA1,
    MP_TYPE_FLAG_NONE,
    make_new, hash_algorithm_sha1_make_new,
    locals_dict, &hash_algorithm_sha1_locals_dict);

static mp_obj_t hash_algorithm_sha256_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_SHA256
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("sha256 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_SHA256)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha256_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA256;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
#endif
}

static const mp_rom_map_elem_t hash_algorithm_sha256_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_sha256)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(32)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_sha256_locals_dict, hash_algorithm_sha256_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_sha256_type,
    MP_QSTR_SHA256,
    MP_TYPE_FLAG_NONE,
    make_new, hash_algorithm_sha256_make_new,
    locals_dict, &hash_algorithm_sha256_locals_dict);

static mp_obj_t hash_algorithm_sha384_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_SHA384
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("sha384 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_SHA384)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha384_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA384;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
#endif
}

static const mp_rom_map_elem_t hash_algorithm_sha384_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_sha384)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(48)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_sha384_locals_dict, hash_algorithm_sha384_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_sha384_type,
    MP_QSTR_SHA384,
    MP_TYPE_FLAG_NONE,
    make_new, hash_algorithm_sha384_make_new,
    locals_dict, &hash_algorithm_sha384_locals_dict);

static mp_obj_t hash_algorithm_sha512_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_SHA512
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("sha512 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_SHA512)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha512_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA512;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
#endif
}

static const mp_rom_map_elem_t hash_algorithm_sha512_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_sha512)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(64)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_sha512_locals_dict, hash_algorithm_sha512_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_sha512_type,
    MP_QSTR_SHA512,
    MP_TYPE_FLAG_NONE,
    make_new, hash_algorithm_sha512_make_new,
    locals_dict, &hash_algorithm_sha512_locals_dict);

static mp_obj_t hash_algorithm_blake2s_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_BLAKE2S
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("blake2s disabled (enable MICROPY_PY_UCRYPTOGRAPHY_BLAKE2S)"));
#else
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_int_t digest_size = 32;
    if (!mp_obj_is_int(args[0]))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected digest_size int"));
    }
    digest_size = mp_obj_get_int(args[0]);
    if (digest_size < 1 || digest_size > 32)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("digest_size must be between 1 and 32 bytes"));
    }
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_blake2s_type;
    HashAlgorithm->md_type = MBEDTLS_MD_NONE_BLAKE2S;
    HashAlgorithm->digest_size = digest_size;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
#endif
}

static void hash_algorithm_blake2s_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_hash_algorithm_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;

    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_digest_size)
            {
                dest[0] = mp_obj_new_int(self->digest_size);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t hash_algorithm_blake2s_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_blake2s)},
    {MP_ROM_QSTR(MP_QSTR_digest_size), MP_ROM_INT(32)},
};

static MP_DEFINE_CONST_DICT(hash_algorithm_blake2s_locals_dict, hash_algorithm_blake2s_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_algorithm_blake2s_type,
    MP_QSTR_BLAKE2s,
    MP_TYPE_FLAG_NONE,
    make_new, hash_algorithm_blake2s_make_new,
    attr, hash_algorithm_blake2s_attr,
    locals_dict, &hash_algorithm_blake2s_locals_dict);

static mp_obj_t hash_context_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_HASH
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("Hash disabled (enable MICROPY_PY_UCRYPTOGRAPHY_HASH)"));
#else
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    if (!mp_obj_is_type(args[0], &hash_algorithm_sha1_type) && !mp_obj_is_type(args[0], &hash_algorithm_sha256_type) && !mp_obj_is_type(args[0], &hash_algorithm_sha384_type) && !mp_obj_is_type(args[0], &hash_algorithm_sha512_type) && !mp_obj_is_type(args[0], &hash_algorithm_blake2s_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }
    mp_hash_context_t *HashContext = m_new_obj(mp_hash_context_t);
    HashContext->base.type = &hash_context_type;
    HashContext->algorithm = args[0];
    HashContext->data = vstr_new(0);
    HashContext->finalized = false;
    return MP_OBJ_FROM_PTR(HashContext);
#endif
}

static mp_obj_t hash_algorithm_update(mp_obj_t obj, mp_obj_t data)
{
    mp_hash_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    vstr_add_strn(self->data, bufinfo_data.buf, bufinfo_data.len);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_hash_algorithm_update_obj, hash_algorithm_update);

static mp_obj_t hash_algorithm_copy(mp_obj_t obj)
{
    mp_hash_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_hash_context_t *HashContext = m_new_obj(mp_hash_context_t);
    HashContext->base.type = &hash_context_type;
    HashContext->algorithm = self->algorithm;
    HashContext->data = vstr_new(self->data->len);
    vstr_add_strn(HashContext->data, self->data->buf, self->data->len);
    HashContext->finalized = false;

    return MP_OBJ_FROM_PTR(HashContext);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hash_algorithm_copy_obj, hash_algorithm_copy);

static mp_obj_t hash_algorithm_finalize(mp_obj_t obj)
{
    mp_hash_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    self->finalized = true;

    vstr_t vstr_digest;
    if (self->algorithm->md_type == MBEDTLS_MD_NONE_BLAKE2S)
    {
        vstr_init_len(&vstr_digest, self->algorithm->digest_size);
        blake2s((byte *)vstr_digest.buf, vstr_digest.len, (const byte *)self->data->buf, self->data->len, NULL, 0);
    }
    else
    {
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(self->algorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)self->data->buf, self->data->len, (byte *)vstr_digest.buf);
    }

    vstr_clear(self->data);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_digest.buf, vstr_digest.len);
    vstr_clear(&vstr_digest);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hash_algorithm_finalize_obj, hash_algorithm_finalize);

static void hash_context_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_hash_context_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_algorithm)
            {
                dest[0] = self->algorithm;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t hash_context_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_algorithm), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&mod_hash_algorithm_update_obj)},
    {MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&mod_hash_algorithm_copy_obj)},
    {MP_ROM_QSTR(MP_QSTR_finalize), MP_ROM_PTR(&mod_hash_algorithm_finalize_obj)},
};

static MP_DEFINE_CONST_DICT(hash_context_locals_dict, hash_context_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hash_context_type,
    MP_QSTR_HashContext,
    MP_TYPE_FLAG_NONE,
    make_new, hash_context_make_new,
    attr, hash_context_attr,
    locals_dict, &hash_context_locals_dict);

static mp_obj_t hmac_context_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_HMAC
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("HMAC disabled (enable MICROPY_PY_UCRYPTOGRAPHY_HMAC)"));
#else
    mp_arg_check_num(n_args, n_kw, 2, 2, false);
    if (!mp_obj_is_type(args[0], &mp_type_bytes))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected key bytes"));
    }
    if (!mp_obj_is_type(args[1], &hash_algorithm_sha1_type) && !mp_obj_is_type(args[1], &hash_algorithm_sha256_type) && !mp_obj_is_type(args[1], &hash_algorithm_sha384_type) && !mp_obj_is_type(args[1], &hash_algorithm_sha512_type) && !mp_obj_is_type(args[1], &hash_algorithm_blake2s_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    mp_hash_context_t *HashContext = m_new_obj(mp_hash_context_t);
    HashContext->base.type = &hash_context_type;
    HashContext->algorithm = args[1];
    HashContext->data = vstr_new(0);
    HashContext->finalized = false;

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(args[0], &bufinfo_key, MP_BUFFER_READ);

    mp_hmac_context_t *HMACContext = m_new_obj(mp_hmac_context_t);
    HMACContext->base.type = &hmac_context_type;
    HMACContext->key = vstr_new(bufinfo_key.len);
    vstr_add_strn(HMACContext->key, bufinfo_key.buf, bufinfo_key.len);
    HMACContext->data = vstr_new(0);
    HMACContext->finalized = false;
    HMACContext->hash_context = HashContext;

    return MP_OBJ_FROM_PTR(HMACContext);
#endif
}

static mp_obj_t hmac_algorithm_update(mp_obj_t obj, mp_obj_t data)
{
    mp_hmac_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    vstr_add_strn(self->data, bufinfo_data.buf, bufinfo_data.len);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_hmac_algorithm_update_obj, hmac_algorithm_update);

static mp_obj_t hmac_algorithm_copy(mp_obj_t obj)
{
    mp_hmac_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_hash_context_t *HashContext = m_new_obj(mp_hash_context_t);
    HashContext->base.type = &hash_context_type;
    HashContext->algorithm = self->hash_context->algorithm;
    HashContext->data = vstr_new(0);
    HashContext->finalized = false;

    mp_hmac_context_t *HMACContext = m_new_obj(mp_hmac_context_t);
    HMACContext->base.type = &hmac_context_type;
    HMACContext->key = vstr_new(self->key->len);
    vstr_add_strn(HMACContext->key, self->key->buf, self->key->len);
    HMACContext->data = vstr_new(self->data->len);
    vstr_add_strn(HMACContext->data, self->data->buf, self->data->len);
    HMACContext->finalized = false;
    HMACContext->hash_context = HashContext;

    return MP_OBJ_FROM_PTR(HMACContext);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hmac_algorithm_copy_obj, hmac_algorithm_copy);

static mp_obj_t hmac_algorithm_finalize(mp_obj_t obj);

static mp_obj_t hmac_algorithm_verify(mp_obj_t obj, mp_obj_t data)
{
    mp_hmac_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_signature;
    mp_get_buffer_raise(data, &bufinfo_signature, MP_BUFFER_READ);

    // Recompute the HMAC over the accumulated data (this also finalizes the
    // context and clears the key/data) and compare it in constant time to the
    // caller-supplied signature. Fail closed on any mismatch so a forged or
    // truncated tag can never be silently accepted.
    mp_obj_t digest_obj = hmac_algorithm_finalize(obj);
    mp_buffer_info_t bufinfo_digest;
    mp_get_buffer_raise(digest_obj, &bufinfo_digest, MP_BUFFER_READ);

    if (!constant_time_bytes_eq((uint8_t *)bufinfo_digest.buf, bufinfo_digest.len, (uint8_t *)bufinfo_signature.buf, bufinfo_signature.len))
    {
        mp_raise_msg(&mp_type_InvalidSignature, NULL);
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_hmac_algorithm_verify_obj, hmac_algorithm_verify);

static mp_obj_t hmac_algorithm_finalize(mp_obj_t obj)
{
    mp_hmac_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    self->finalized = true;

    vstr_t vstr_digest;
    if (self->hash_context->algorithm->md_type == MBEDTLS_MD_NONE_BLAKE2S)
    {
        size_t block_size = 64;
        vstr_t vstr_ipad;
        vstr_t vstr_opad;
        vstr_init_len(&vstr_digest, self->hash_context->algorithm->digest_size);
        vstr_init_len(&vstr_ipad, block_size);
        vstr_init_len(&vstr_opad, block_size);

        const byte *key = (const byte *)self->key->buf;
        size_t keylen = self->key->len;

        if (keylen > (size_t)block_size)
        {
            blake2s((byte *)vstr_digest.buf, vstr_digest.len, key, keylen, NULL, 0);
            keylen = vstr_digest.len;
            key = (byte *)vstr_digest.buf;
        }

        byte *ipad = (byte *)vstr_ipad.buf;
        byte *opad = (byte *)vstr_opad.buf;

        memset(ipad, 0x36, block_size);
        memset(opad, 0x5C, block_size);

        for (size_t i = 0; i < keylen; i++)
        {
            ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
            opad[i] = (unsigned char)(opad[i] ^ key[i]);
        }

        blake2s_state S[1];
        blake2s_init(S, vstr_digest.len);
        blake2s_update(S, ipad, block_size);
        blake2s_update(S, (const byte *)self->data->buf, self->data->len);
        blake2s_final(S, (byte *)vstr_digest.buf, vstr_digest.len);

        blake2s_init(S, vstr_digest.len);
        blake2s_update(S, opad, block_size);
        blake2s_update(S, (byte *)vstr_digest.buf, vstr_digest.len);
        blake2s_final(S, (byte *)vstr_digest.buf, vstr_digest.len);
        vstr_clear(&vstr_ipad);
        vstr_clear(&vstr_opad);
    }
    else
    {
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(self->hash_context->algorithm->md_type)));
        mbedtls_md_hmac(mbedtls_md_info_from_type(self->hash_context->algorithm->md_type), (const byte *)self->key->buf, self->key->len, (const byte *)self->data->buf, self->data->len, (byte *)vstr_digest.buf);
    }

    vstr_clear(self->key);
    vstr_clear(self->data);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_digest.buf, vstr_digest.len);
    vstr_clear(&vstr_digest);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hmac_algorithm_finalize_obj, hmac_algorithm_finalize);

static const mp_rom_map_elem_t hmac_context_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&mod_hmac_algorithm_update_obj)},
    {MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&mod_hmac_algorithm_copy_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&mod_hmac_algorithm_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_finalize), MP_ROM_PTR(&mod_hmac_algorithm_finalize_obj)},
};

static MP_DEFINE_CONST_DICT(hmac_context_locals_dict, hmac_context_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hmac_context_type,
    MP_QSTR_HMACContext,
    MP_TYPE_FLAG_NONE,
    make_new, hmac_context_make_new,
    locals_dict, &hmac_context_locals_dict);

static mp_obj_t x509_public_key(mp_obj_t obj)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(obj);
    if (self->ec_public_key != NULL)
    {
        return self->ec_public_key;
    }
    else if (self->rsa_public_key != NULL)
    {
        return self->rsa_public_key;
    }
    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_public_key_obj, x509_public_key);

static mp_obj_t x509_public_bytes(size_t n_args, const mp_obj_t *args)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(args[0]);
    mp_int_t encoding = SERIALIZATION_ENCODING_DER;
    if (n_args == 2)
    {
        encoding = mp_obj_get_int(args[1]);
    }
    if (encoding == SERIALIZATION_ENCODING_DER)
    {
        return self->certificate_bytes;
    }
    else if (encoding == SERIALIZATION_ENCODING_PEM)
    {
        mp_buffer_info_t der;
        mp_get_buffer_raise(self->certificate_bytes, &der, MP_BUFFER_READ);
        size_t olen = 0;
        mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", (const byte *)der.buf, der.len, NULL, 0, &olen);
        vstr_t vstr_pem;
        vstr_init_len(&vstr_pem, olen);
        int ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", (const byte *)der.buf, der.len, (byte *)vstr_pem.buf, olen, &olen);
        if (ret != 0)
        {
            vstr_clear(&vstr_pem);
            mp_raise_ValueError(MP_ERROR_TEXT("PEM encoding failed"));
        }
        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_pem.buf, olen > 0 ? olen - 1 : 0);
        vstr_clear(&vstr_pem);
        return oo;
    }
    mp_raise_ValueError(MP_ERROR_TEXT("Expected encoding value 1 (DER) or 2 (PEM)"));
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_x509_public_bytes_obj, 1, 2, x509_public_bytes);

static void x509_certificate_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_version)
            {
                dest[0] = self->version;
                return;
            }
            if (attr == MP_QSTR_serial_number)
            {
                dest[0] = self->serial_number;
                return;
            }
            if (attr == MP_QSTR_not_valid_before || attr == MP_QSTR_not_valid_before_utc)
            {
                dest[0] = self->not_valid_before;
                return;
            }
            if (attr == MP_QSTR_not_valid_after || attr == MP_QSTR_not_valid_after_utc)
            {
                dest[0] = self->not_valid_after;
                return;
            }
            if (attr == MP_QSTR_subject)
            {
                dest[0] = self->subject;
                return;
            }
            if (attr == MP_QSTR_issuer)
            {
                dest[0] = self->issuer;
                return;
            }
            if (attr == MP_QSTR_signature)
            {
                dest[0] = self->signature;
                return;
            }
            if (attr == MP_QSTR_signature_algorithm_oid)
            {
                dest[0] = self->signature_algorithm_oid;
                return;
            }
            if (attr == MP_QSTR_tbs_certificate_bytes)
            {
                dest[0] = self->tbs_certificate_bytes;
                return;
            }
            if (attr == MP_QSTR_extensions)
            {
                dest[0] = self->extensions;
                return;
            }
            if (attr == MP_QSTR_signature_hash_algorithm)
            {
                dest[0] = self->signature_hash_algorithm;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t x509_certificate_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_x509_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_version), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_serial_number), MP_ROM_INT(0)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_before), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_after), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_before_utc), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_after_utc), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_subject), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_issuer), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature_algorithm_oid), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature_hash_algorithm), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_tbs_certificate_bytes), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_extensions), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_x509_public_bytes_obj)},
};

static MP_DEFINE_CONST_DICT(x509_certificate_locals_dict, x509_certificate_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_certificate_type,
    MP_QSTR_Certificate,
    MP_TYPE_FLAG_NONE,
    attr, x509_certificate_attr,
    locals_dict, &x509_certificate_locals_dict);

#if MICROPY_PY_UCRYPTOGRAPHY_X509
static mp_obj_t x509_crt_parse_oid(const mbedtls_asn1_buf *o, const mp_obj_type_t *type)
{
    vstr_t vstr_oid;
    vstr_init(&vstr_oid, 0);
    unsigned int value = 0;

    for (size_t i = 0; i < o->len; i++)
    {
        if (i == 0)
        {
            // First subidentifier encodes the first two arcs (40*x + y).
            vstr_printf(&vstr_oid, "%d.%d", o->p[0] / 40, o->p[0] % 40);
            continue;
        }

        if (((value << 7) >> 7) != value)
        {
            mp_raise_ValueError(MP_ERROR_TEXT("oid buf too small"));
        }

        value <<= 7;
        value += o->p[i] & 0x7F;

        if (!(o->p[i] & 0x80))
        {
            vstr_printf(&vstr_oid, ".%d", value);
            value = 0;
        }
    }

    mp_obj_t oo = mp_const_none;
    if (type == &mp_type_str)
    {
        oo = mp_obj_new_str(vstr_oid.buf, vstr_oid.len);
        vstr_clear(&vstr_oid);
    }
    else
    {
        oo = mp_obj_new_bytes((const byte *)vstr_oid.buf, vstr_oid.len);
        vstr_clear(&vstr_oid);
    }
    return oo;
}

static mp_obj_t x509_crt_parse_time(const mbedtls_x509_time *t)
{
    vstr_t vstr_time;
    vstr_init(&vstr_time, 0);
    vstr_printf(&vstr_time, "%04d-%02d-%02d %02d:%02d:%02d", t->year, t->mon, t->day, t->hour, t->min, t->sec);
    mp_obj_t oo = mp_obj_new_str(vstr_time.buf, vstr_time.len);
    vstr_clear(&vstr_time);
    return oo;
}

// Wrap a dotted-string object into an x509.ObjectIdentifier.
static mp_obj_t x509_new_oid_from_str(mp_obj_t dotted_string)
{
    mp_x509_oid_t *o = m_new_obj(mp_x509_oid_t);
    o->base.type = &x509_oid_type;
    o->dotted_string = dotted_string;
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_new_extension(mp_obj_t oid, int critical, mp_obj_t value)
{
    mp_x509_extension_t *e = m_new_obj(mp_x509_extension_t);
    e->base.type = &x509_extension_type;
    e->oid = oid;
    e->critical = mp_obj_new_bool(critical);
    e->value = value;
    return MP_OBJ_FROM_PTR(e);
}

static mp_obj_t x509_crt_parse_name(const mbedtls_x509_name *dn)
{
    mp_obj_t attrs = mp_obj_new_list(0, NULL);
    const mbedtls_x509_name *name = dn;
    while (name != NULL)
    {
        if (!name->oid.p)
        {
            name = name->next;
            continue;
        }
        mp_x509_name_attribute_t *na = m_new_obj(mp_x509_name_attribute_t);
        na->base.type = &x509_name_attribute_type;
        na->oid = x509_new_oid_from_str(x509_crt_parse_oid(&name->oid, &mp_type_str));
        na->value = mp_obj_new_str((const char *)name->val.p, name->val.len);
        mp_obj_list_append(attrs, MP_OBJ_FROM_PTR(na));
        name = name->next;
    }
    mp_x509_name_t *nm = m_new_obj(mp_x509_name_t);
    nm->base.type = &x509_name_type;
    nm->attributes = attrs;
    return MP_OBJ_FROM_PTR(nm);
}

static void x509_crt_dump(const mbedtls_x509_crt *crt)
{
    vstr_t vstr_crt;
    vstr_init_len(&vstr_crt, crt->raw.len);
    mbedtls_x509_crt_info(vstr_crt.buf, vstr_crt.len, "", crt);
    mp_printf(&mp_plat_print, "certificate info: %s\n", vstr_crt.buf);
    vstr_clear(&vstr_crt);
}

// Accept (and skip) every unsupported extension, including critical ones, so
// certificates carrying custom critical extensions parse; they are re-read from
// the raw v3 extensions block by x509_build_extensions.
static int x509_ext_cb_accept(void *p_ctx, const mbedtls_x509_crt *crt, const mbedtls_x509_buf *oid, int critical, const unsigned char *p, const unsigned char *end)
{
    (void)p_ctx;
    (void)crt;
    (void)oid;
    (void)critical;
    (void)p;
    (void)end;
    return 0;
}

// Walk the raw v3 extensions (Extension ::= SEQUENCE { extnID, critical BOOLEAN
// DEFAULT FALSE, extnValue OCTET STRING }) to build a PyCA-like Extensions object
// preserving order, criticality and per-extension typed values.
static mp_obj_t x509_build_extensions(const mbedtls_x509_crt *crt)
{
    mp_obj_t list = mp_obj_new_list(0, NULL);
    if (crt->v3_ext.p != NULL && crt->v3_ext.len > 0)
    {
        // v3_ext.p points at the outer "SEQUENCE OF Extension" tag; consume it first.
        unsigned char *p = crt->v3_ext.p;
        const unsigned char *end = crt->v3_ext.p + crt->v3_ext.len;
        size_t seq_len;
        if (mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0)
        {
            end = p + seq_len;
        }
        while (p < end)
        {
            size_t len;
            if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
            {
                break;
            }
            unsigned char *ext_end = p + len;

            mbedtls_x509_buf extn_oid;
            memset(&extn_oid, 0, sizeof(extn_oid));
            if (mbedtls_asn1_get_tag(&p, ext_end, &extn_oid.len, MBEDTLS_ASN1_OID) != 0)
            {
                break;
            }
            extn_oid.tag = MBEDTLS_ASN1_OID;
            extn_oid.p = p;
            p += extn_oid.len;

            int is_critical = 0;
            int ret = mbedtls_asn1_get_bool(&p, ext_end, &is_critical);
            if (ret != 0 && ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            {
                break;
            }

            size_t val_len;
            if (mbedtls_asn1_get_tag(&p, ext_end, &val_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
            {
                break;
            }
            const unsigned char *val_p = p;
            p = ext_end;

            mp_obj_t oid_obj = x509_new_oid_from_str(x509_crt_parse_oid(&extn_oid, &mp_type_str));

            int ext_type = 0;
            mp_obj_t value = mp_const_none;
            if (mbedtls_oid_get_x509_ext_type(&extn_oid, &ext_type) == 0 &&
                (ext_type == MBEDTLS_X509_EXT_BASIC_CONSTRAINTS ||
                 ext_type == MBEDTLS_X509_EXT_KEY_USAGE ||
                 ext_type == MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE ||
                 ext_type == MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER ||
                 ext_type == MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER ||
                 ext_type == MBEDTLS_X509_EXT_SUBJECT_ALT_NAME))
            {
                switch (ext_type)
                {
                case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
                {
                    mp_x509_basic_constraints_t *bc = m_new_obj(mp_x509_basic_constraints_t);
                    bc->base.type = &x509_basic_constraints_type;
                    bc->ca = crt->private_ca_istrue ? true : false;
                    // mbedtls stores max_pathlen as RFC5280 value + 1; 0 means absent.
                    bc->path_length = (crt->private_max_pathlen > 0) ? mp_obj_new_int(crt->private_max_pathlen - 1) : mp_const_none;
                    value = MP_OBJ_FROM_PTR(bc);
                    break;
                }
                case MBEDTLS_X509_EXT_KEY_USAGE:
                {
                    mp_x509_key_usage_t *ku = m_new_obj(mp_x509_key_usage_t);
                    ku->base.type = &x509_key_usage_type;
                    ku->flags = crt->private_key_usage;
                    value = MP_OBJ_FROM_PTR(ku);
                    break;
                }
                case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
                {
                    mp_obj_t usages = mp_obj_new_list(0, NULL);
                    const mbedtls_x509_sequence *cur = &crt->ext_key_usage;
                    while (cur != NULL && cur->buf.p != NULL)
                    {
                        mp_obj_list_append(usages, x509_new_oid_from_str(x509_crt_parse_oid(&cur->buf, &mp_type_str)));
                        cur = cur->next;
                    }
                    mp_x509_ext_key_usage_t *eku = m_new_obj(mp_x509_ext_key_usage_t);
                    eku->base.type = &x509_ext_key_usage_type;
                    eku->usages = usages;
                    value = MP_OBJ_FROM_PTR(eku);
                    break;
                }
                case MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER:
                {
                    mp_x509_ski_t *ski = m_new_obj(mp_x509_ski_t);
                    ski->base.type = &x509_ski_type;
                    ski->digest = mp_obj_new_bytes(crt->subject_key_id.p, crt->subject_key_id.len);
                    value = MP_OBJ_FROM_PTR(ski);
                    break;
                }
                case MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER:
                {
                    mp_x509_aki_t *aki = m_new_obj(mp_x509_aki_t);
                    aki->base.type = &x509_aki_type;
                    aki->key_identifier = mp_obj_new_bytes(crt->authority_key_id.keyIdentifier.p, crt->authority_key_id.keyIdentifier.len);
                    value = MP_OBJ_FROM_PTR(aki);
                    break;
                }
                case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
                {
                    mp_obj_t gnames = mp_obj_new_list(0, NULL);
                    const mbedtls_x509_sequence *cur = &crt->subject_alt_names;
                    while (cur != NULL && cur->buf.p != NULL)
                    {
                        mbedtls_x509_subject_alternative_name san;
                        memset(&san, 0, sizeof(san));
                        int sret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
                        mp_x509_general_name_t *g = m_new_obj(mp_x509_general_name_t);
                        if (sret == 0 && (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_RFC822_NAME || san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER))
                        {
                            g->base.type = &x509_dns_name_type;
                            g->kind = 2;
                            g->value = mp_obj_new_str((const char *)san.san.unstructured_name.p, san.san.unstructured_name.len);
                        }
                        else
                        {
                            g->base.type = &x509_ip_address_type;
                            g->kind = 7;
                            g->value = mp_obj_new_bytes(cur->buf.p, cur->buf.len);
                        }
                        if (sret == 0)
                        {
                            mbedtls_x509_free_subject_alt_name(&san);
                        }
                        mp_obj_list_append(gnames, MP_OBJ_FROM_PTR(g));
                        cur = cur->next;
                    }
                    mp_x509_san_t *san_o = m_new_obj(mp_x509_san_t);
                    san_o->base.type = &x509_san_type;
                    san_o->general_names = gnames;
                    value = MP_OBJ_FROM_PTR(san_o);
                    break;
                }
                }
            }
            else
            {
                mp_x509_unrecognized_extension_t *ue = m_new_obj(mp_x509_unrecognized_extension_t);
                ue->base.type = &x509_unrecognized_extension_type;
                ue->oid = oid_obj;
                ue->value = mp_obj_new_bytes(val_p, val_len);
                value = MP_OBJ_FROM_PTR(ue);
            }

            mp_obj_list_append(list, x509_new_extension(oid_obj, is_critical, value));
        }
    }
    mp_x509_extensions_t *exts = m_new_obj(mp_x509_extensions_t);
    exts->base.type = &x509_extensions_type;
    exts->list = list;
    return MP_OBJ_FROM_PTR(exts);
}

static mp_obj_t x509_crt_parse_der(mp_obj_t certificate)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(certificate, &bufinfo, MP_BUFFER_READ);

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der_with_ext_cb(&crt, (const byte *)bufinfo.buf, bufinfo.len, 0, x509_ext_cb_accept, NULL) != 0)
    {
        x509_crt_dump(&crt);
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError(MP_ERROR_TEXT("Certificate format"));
    }

    if ((crt.private_sig_md != MBEDTLS_MD_SHA1) && (crt.private_sig_md != MBEDTLS_MD_SHA256) && (crt.private_sig_md != MBEDTLS_MD_SHA384) && (crt.private_sig_md != MBEDTLS_MD_SHA512))
    {
        x509_crt_dump(&crt);
        mbedtls_x509_crt_free(&crt);
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("only SHA1, SHA256, SHA384 or SHA512 are supported"));
    }

    if (crt.private_sig_pk != MBEDTLS_PK_ECDSA && crt.private_sig_pk != MBEDTLS_PK_RSA)
    {
        x509_crt_dump(&crt);
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError(MP_ERROR_TEXT("only ECDSA and RSA are supported"));
    }

    mp_obj_t extensions = x509_build_extensions(&crt);
    mp_obj_t signature_algorithm_oid = x509_new_oid_from_str(x509_crt_parse_oid(&crt.sig_oid, &mp_type_str));

    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->md_type = crt.private_sig_md;
    switch (HashAlgorithm->md_type)
    {
    case MBEDTLS_MD_SHA1:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha1_type;
        break;
    }
    case MBEDTLS_MD_SHA256:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha256_type;
        break;
    }
    case MBEDTLS_MD_SHA384:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha384_type;
        break;
    }
    case MBEDTLS_MD_SHA512:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha512_type;
        break;
    }
    default:
    {
        break;
    }
    }

    mp_x509_certificate_t *Certificate = m_new_obj(mp_x509_certificate_t);
    Certificate->base.type = &x509_certificate_type;
    Certificate->version = mp_obj_new_int(crt.version);
    Certificate->serial_number = mp_obj_int_from_bytes_impl(true, crt.serial.len, crt.serial.p);
    Certificate->not_valid_before = x509_crt_parse_time(&crt.valid_from);
    Certificate->not_valid_after = x509_crt_parse_time(&crt.valid_to);
    Certificate->subject = x509_crt_parse_name(&crt.subject);
    Certificate->issuer = x509_crt_parse_name(&crt.issuer);
    Certificate->signature = mp_obj_new_bytes(crt.private_sig.p, crt.private_sig.len);
    Certificate->signature_algorithm_oid = signature_algorithm_oid;
    Certificate->signature_hash_algorithm = HashAlgorithm;
    Certificate->extensions = extensions;
    Certificate->tbs_certificate_bytes = mp_obj_new_bytes(crt.tbs.p, crt.tbs.len);
    Certificate->certificate_bytes = mp_obj_new_bytes(crt.raw.p, crt.raw.len);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, crt.pk_raw.p, crt.pk_raw.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mbedtls_x509_crt_free(&crt);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("public key"));
    }

    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY)
    {
        Certificate->rsa_public_key = NULL;
        Certificate->ec_public_key = ec_parse_keypair(mbedtls_pk_ec(pk), false);
        Certificate->public_bytes = Certificate->ec_public_key->public_bytes;
    }
    else if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA)
    {
        Certificate->ec_public_key = NULL;
        Certificate->rsa_public_key = rsa_parse_keypair(mbedtls_pk_rsa(pk), false);
        Certificate->public_bytes = Certificate->rsa_public_key->public_bytes;
    }
    else
    {
        mbedtls_pk_free(&pk);
        mbedtls_x509_crt_free(&crt);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("only EC or RSA kes are supported"));
    }

    mbedtls_pk_free(&pk);
    mbedtls_x509_crt_free(&crt);
    return Certificate;
}
#else
static mp_obj_t x509_crt_parse_der(mp_obj_t certificate)
{
    (void)certificate;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509)"));
}
#endif

static MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_crt_parse_der_obj, x509_crt_parse_der);

// ===== X.509 certificate creation (PyCA cryptography-compatible) =====

static mp_obj_t x509_oid_new(const char *dotted)
{
    mp_x509_oid_t *o = m_new_obj(mp_x509_oid_t);
    o->base.type = &x509_oid_type;
    o->dotted_string = mp_obj_new_str(dotted, strlen(dotted));
    return MP_OBJ_FROM_PTR(o);
}

static const char *x509_oid_get_dotted(mp_obj_t o)
{
    if (mp_obj_is_type(o, &x509_oid_type))
    {
        return mp_obj_str_get_str(((mp_x509_oid_t *)MP_OBJ_TO_PTR(o))->dotted_string);
    }
    return mp_obj_str_get_str(o);
}

// Map a dotted OID to the mbedtls RDN short name, else return the dotted OID
// (mbedtls_x509_string_to_names accepts numeric OIDs too).
static const char *x509_oid_to_name_key(mp_obj_t oid_obj)
{
    const char *d = x509_oid_get_dotted(oid_obj);
    static const struct
    {
        const char *dotted;
        const char *key;
    } map[] = {
        {"2.5.4.3", "CN"},
        {"2.5.4.6", "C"},
        {"2.5.4.7", "L"},
        {"2.5.4.8", "ST"},
        {"2.5.4.10", "O"},
        {"2.5.4.11", "OU"},
        {"2.5.4.5", "serialNumber"},
        {"1.2.840.113549.1.9.1", "emailAddress"},
        {"0.9.2342.19200300.100.1.25", "DC"},
    };
    for (size_t i = 0; i < MP_ARRAY_SIZE(map); i++)
    {
        if (strcmp(d, map[i].dotted) == 0)
        {
            return map[i].key;
        }
    }
    return d;
}

#if MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE
static void x509_name_to_string(mp_obj_t name_obj, vstr_t *out)
{
    mp_x509_name_t *name = MP_OBJ_TO_PTR(name_obj);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(name->attributes, &n, &items);
    for (size_t i = 0; i < n; i++)
    {
        mp_x509_name_attribute_t *na = MP_OBJ_TO_PTR(items[i]);
        if (i > 0)
        {
            vstr_add_byte(out, ',');
        }
        vstr_add_str(out, x509_oid_to_name_key(na->oid));
        vstr_add_byte(out, '=');
        size_t vl;
        const char *v = mp_obj_str_get_data(na->value, &vl);
        for (size_t j = 0; j < vl; j++)
        {
            char ch = v[j];
            if (ch == ',' || ch == '+' || ch == '\\')
            {
                vstr_add_byte(out, '\\');
            }
            vstr_add_byte(out, ch);
        }
    }
}

static void x509_datetime_to_string(mp_obj_t dt, vstr_t *out)
{
    mp_int_t year = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_year));
    mp_int_t month = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_month));
    mp_int_t day = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_day));
    mp_int_t hour = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_hour));
    mp_int_t minute = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_minute));
    mp_int_t second = mp_obj_get_int(mp_load_attr(dt, MP_QSTR_second));
    vstr_printf(out, "%04d%02d%02d%02d%02d%02d", (int)year, (int)month, (int)day, (int)hour, (int)minute, (int)second);
}

static mbedtls_md_type_t x509_hash_to_md(mp_obj_t algorithm)
{
    if (mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) || mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) || mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) || mp_obj_is_type(algorithm, &hash_algorithm_sha512_type))
    {
        return ((mp_hash_algorithm_t *)MP_OBJ_TO_PTR(algorithm))->md_type;
    }
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes SHA1, SHA256, SHA384 or SHA512"));
    return MBEDTLS_MD_NONE;
}

static void crypto_pk_from_public_key(mbedtls_pk_context *pk, mp_obj_t key)
{
    if (mp_obj_is_type(key, &ec_private_key_type))
    {
        key = ((mp_ec_private_key_t *)MP_OBJ_TO_PTR(key))->public_key;
    }
    else if (mp_obj_is_type(key, &rsa_private_key_type))
    {
        key = ((mp_rsa_private_key_t *)MP_OBJ_TO_PTR(key))->public_key;
    }

    if (mp_obj_is_type(key, &ec_public_key_type))
    {
        mp_ec_public_key_t *k = MP_OBJ_TO_PTR(key);
        mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pk);
        mbedtls_ecp_group_load(&ecp->private_grp, k->public_numbers->curve->ecp_group_id);
        mp_buffer_info_t pub;
        mp_get_buffer_raise(k->public_bytes, &pub, MP_BUFFER_READ);
        if (mbedtls_ecp_point_read_binary(&ecp->private_grp, &ecp->private_Q, (const byte *)pub.buf, pub.len) != 0)
        {
            mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("ec public key"));
        }
    }
    else if (mp_obj_is_type(key, &rsa_public_key_type))
    {
        mp_rsa_public_key_t *k = MP_OBJ_TO_PTR(key);
        mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
        mbedtls_mpi N, E;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&E);
        mbedtls_mpi_read_binary_from_mp_obj(&N, k->public_numbers->n, true);
        mbedtls_mpi_read_binary_from_mp_obj(&E, k->public_numbers->e, true);
        int ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E);
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        if (ret != 0)
        {
            mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("rsa public key"));
        }
    }
    else
    {
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("Expected EC or RSA public key"));
    }
}

static void crypto_pk_from_private_key(mbedtls_pk_context *pk, mp_obj_t key)
{
    if (mp_obj_is_type(key, &ec_private_key_type))
    {
        mp_ec_private_key_t *k = MP_OBJ_TO_PTR(key);
        mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pk);
        mbedtls_ecp_group_load(&ecp->private_grp, k->curve->ecp_group_id);
        mp_buffer_info_t priv;
        mp_get_buffer_raise(k->private_bytes, &priv, MP_BUFFER_READ);
        if (mbedtls_mpi_read_binary(&ecp->private_d, (const byte *)priv.buf, priv.len) != 0)
        {
            mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("ec private key"));
        }
        mp_buffer_info_t pub;
        mp_get_buffer_raise(k->public_key->public_bytes, &pub, MP_BUFFER_READ);
        if (mbedtls_ecp_point_read_binary(&ecp->private_grp, &ecp->private_Q, (const byte *)pub.buf, pub.len) != 0)
        {
            mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("ec public point"));
        }
    }
    else if (mp_obj_is_type(key, &rsa_private_key_type))
    {
        mp_rsa_private_key_t *k = MP_OBJ_TO_PTR(key);
        mp_rsa_private_numbers_t *pn = k->private_numbers;
        mp_rsa_public_numbers_t *pubn = k->public_key->public_numbers;
        mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
        mbedtls_mpi N, E, P, Q, D;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&E);
        mbedtls_mpi_init(&P);
        mbedtls_mpi_init(&Q);
        mbedtls_mpi_init(&D);
        mbedtls_mpi_read_binary_from_mp_obj(&N, pubn->n, true);
        mbedtls_mpi_read_binary_from_mp_obj(&E, pubn->e, true);
        mbedtls_mpi_read_binary_from_mp_obj(&P, pn->p, true);
        mbedtls_mpi_read_binary_from_mp_obj(&Q, pn->q, true);
        mbedtls_mpi_read_binary_from_mp_obj(&D, pn->d, true);
        int ret = mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E);
        if (ret == 0)
        {
            ret = mbedtls_rsa_complete(rsa);
        }
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        mbedtls_mpi_free(&P);
        mbedtls_mpi_free(&Q);
        mbedtls_mpi_free(&D);
        if (ret != 0)
        {
            mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("rsa private key"));
        }
    }
    else
    {
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("Expected EC or RSA private key"));
    }
}

static int x509_set_extension_generic(void *ctx, bool is_csr, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len)
{
#if MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
    if (is_csr)
    {
        return mbedtls_x509write_csr_set_extension((mbedtls_x509write_csr *)ctx, oid, oid_len, critical, val, val_len);
    }
#else
    (void)is_csr;
#endif
    return mbedtls_x509write_crt_set_extension((mbedtls_x509write_cert *)ctx, oid, oid_len, critical, val, val_len);
}

static int x509_apply_extension(void *ctx, bool is_csr, mp_obj_t ext, bool critical)
{
    if (mp_obj_is_type(ext, &x509_san_type))
    {
        mp_x509_san_t *san = MP_OBJ_TO_PTR(ext);
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(san->general_names, &n, &items);
        unsigned char buf[1024];
        unsigned char *c = buf + sizeof(buf);
        size_t len = 0;
        int ret;
        for (size_t i = n; i > 0; i--)
        {
            mp_x509_general_name_t *g = MP_OBJ_TO_PTR(items[i - 1]);
            mp_buffer_info_t vb;
            if (g->kind == 7)
            {
                mp_get_buffer_raise(g->value, &vb, MP_BUFFER_READ);
            }
            else
            {
                size_t sl;
                const char *s = mp_obj_str_get_data(g->value, &sl);
                vb.buf = (void *)s;
                vb.len = sl;
            }
            if ((ret = mbedtls_asn1_write_raw_buffer(&c, buf, (const unsigned char *)vb.buf, vb.len)) < 0)
            {
                return ret;
            }
            len += ret;
            if ((ret = mbedtls_asn1_write_len(&c, buf, vb.len)) < 0)
            {
                return ret;
            }
            len += ret;
            if ((ret = mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | (unsigned char)g->kind)) < 0)
            {
                return ret;
            }
            len += ret;
        }
        if ((ret = mbedtls_asn1_write_len(&c, buf, len)) < 0)
        {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0)
        {
            return ret;
        }
        len += ret;
        return x509_set_extension_generic(ctx, is_csr, MBEDTLS_OID_SUBJECT_ALT_NAME, MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), critical, c, len);
    }
    else if (mp_obj_is_type(ext, &x509_basic_constraints_type))
    {
        mp_x509_basic_constraints_t *bc = MP_OBJ_TO_PTR(ext);
        unsigned char buf[16];
        unsigned char *c = buf + sizeof(buf);
        size_t len = 0;
        int ret;
        if (bc->ca)
        {
            if (bc->path_length != mp_const_none)
            {
                if ((ret = mbedtls_asn1_write_int(&c, buf, mp_obj_get_int(bc->path_length))) < 0)
                {
                    return ret;
                }
                len += ret;
            }
            if ((ret = mbedtls_asn1_write_bool(&c, buf, 1)) < 0)
            {
                return ret;
            }
            len += ret;
        }
        if ((ret = mbedtls_asn1_write_len(&c, buf, len)) < 0)
        {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0)
        {
            return ret;
        }
        len += ret;
        return x509_set_extension_generic(ctx, is_csr, MBEDTLS_OID_BASIC_CONSTRAINTS, MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS), critical, c, len);
    }
    else if (mp_obj_is_type(ext, &x509_key_usage_type))
    {
        mp_x509_key_usage_t *ku = MP_OBJ_TO_PTR(ext);
        unsigned char buf[5] = {0};
        unsigned char bits[2];
        bits[0] = (unsigned char)(ku->flags & 0xFF);
        bits[1] = (unsigned char)((ku->flags >> 8) & 0xFF);
        unsigned char *c = buf + sizeof(buf);
        int ret = mbedtls_asn1_write_named_bitstring(&c, buf, bits, 9);
        if (ret < 0)
        {
            return ret;
        }
        return x509_set_extension_generic(ctx, is_csr, MBEDTLS_OID_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE), critical, c, (size_t)ret);
    }
    else if (mp_obj_is_type(ext, &x509_ext_key_usage_type))
    {
        mp_x509_ext_key_usage_t *eku = MP_OBJ_TO_PTR(ext);
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(eku->usages, &n, &items);
        if (n == 0)
        {
            return 0;
        }
        unsigned char buf[256];
        unsigned char *c = buf + sizeof(buf);
        size_t len = 0;
        int ret;
        for (size_t i = n; i > 0; i--)
        {
            const char *dotted = x509_oid_get_dotted(items[i - 1]);
            const char *der = NULL;
            size_t der_len = 0;
            if (strcmp(dotted, "1.3.6.1.5.5.7.3.1") == 0)
            {
                der = MBEDTLS_OID_SERVER_AUTH;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
            }
            else if (strcmp(dotted, "1.3.6.1.5.5.7.3.2") == 0)
            {
                der = MBEDTLS_OID_CLIENT_AUTH;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
            }
            else if (strcmp(dotted, "1.3.6.1.5.5.7.3.3") == 0)
            {
                der = MBEDTLS_OID_CODE_SIGNING;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING);
            }
            else if (strcmp(dotted, "1.3.6.1.5.5.7.3.4") == 0)
            {
                der = MBEDTLS_OID_EMAIL_PROTECTION;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EMAIL_PROTECTION);
            }
            else if (strcmp(dotted, "1.3.6.1.5.5.7.3.8") == 0)
            {
                der = MBEDTLS_OID_TIME_STAMPING;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_TIME_STAMPING);
            }
            else if (strcmp(dotted, "1.3.6.1.5.5.7.3.9") == 0)
            {
                der = MBEDTLS_OID_OCSP_SIGNING;
                der_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING);
            }
            else
            {
                return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
            }
            if ((ret = mbedtls_asn1_write_oid(&c, buf, der, der_len)) < 0)
            {
                return ret;
            }
            len += ret;
        }
        if ((ret = mbedtls_asn1_write_len(&c, buf, len)) < 0)
        {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0)
        {
            return ret;
        }
        len += ret;
        return x509_set_extension_generic(ctx, is_csr, MBEDTLS_OID_EXTENDED_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE), critical, c, len);
    }
    else if (mp_obj_is_type(ext, &x509_ski_type))
    {
        if (is_csr)
        {
            return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
        }
        return mbedtls_x509write_crt_set_subject_key_identifier((mbedtls_x509write_cert *)ctx);
    }
    else if (mp_obj_is_type(ext, &x509_aki_type))
    {
        if (is_csr)
        {
            return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
        }
        return mbedtls_x509write_crt_set_authority_key_identifier((mbedtls_x509write_cert *)ctx);
    }
    else if (mp_obj_is_type(ext, &x509_unrecognized_extension_type))
    {
        mp_x509_unrecognized_extension_t *ue = MP_OBJ_TO_PTR(ext);
        const char *dotted = x509_oid_get_dotted(ue->oid);
        mp_buffer_info_t val;
        mp_get_buffer_raise(ue->value, &val, MP_BUFFER_READ);
        mbedtls_asn1_buf oidbuf;
        memset(&oidbuf, 0, sizeof(oidbuf));
        int ret = mbedtls_oid_from_numeric_string(&oidbuf, dotted, strlen(dotted));
        if (ret != 0)
        {
            return ret;
        }
        ret = x509_set_extension_generic(ctx, is_csr, (const char *)oidbuf.p, oidbuf.len, critical, (const unsigned char *)val.buf, val.len);
        mbedtls_free(oidbuf.p);
        return ret;
    }
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported extension"));
    return -1;
}
#endif

// PyCA-compatible human-readable name for the OID repr; "Unknown OID" otherwise.
static const char *x509_oid_name_from_dotted(const char *d)
{
    static const struct
    {
        const char *dotted;
        const char *name;
    } map[] = {
        {"2.5.4.3", "commonName"},
        {"2.5.4.6", "countryName"},
        {"2.5.4.7", "localityName"},
        {"2.5.4.8", "stateOrProvinceName"},
        {"2.5.4.10", "organizationName"},
        {"2.5.4.11", "organizationalUnitName"},
        {"2.5.4.5", "serialNumber"},
        {"1.2.840.113549.1.9.1", "emailAddress"},
        {"0.9.2342.19200300.100.1.25", "domainComponent"},
        {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
        {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
        {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
        {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
        {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
        {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
        {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
        {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
        {"2.5.29.14", "subjectKeyIdentifier"},
        {"2.5.29.15", "keyUsage"},
        {"2.5.29.17", "subjectAltName"},
        {"2.5.29.19", "basicConstraints"},
        {"2.5.29.35", "authorityKeyIdentifier"},
        {"2.5.29.37", "extendedKeyUsage"},
        {"1.3.6.1.5.5.7.3.1", "serverAuth"},
        {"1.3.6.1.5.5.7.3.2", "clientAuth"},
        {"1.3.6.1.5.5.7.3.3", "codeSigning"},
        {"1.3.6.1.5.5.7.3.4", "emailProtection"},
        {"1.3.6.1.5.5.7.3.8", "timeStamping"},
        {"1.3.6.1.5.5.7.3.9", "OCSPSigning"},
    };
    for (size_t i = 0; i < MP_ARRAY_SIZE(map); i++)
    {
        if (strcmp(d, map[i].dotted) == 0)
        {
            return map[i].name;
        }
    }
    return "Unknown OID";
}

static void x509_oid_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    const char *dotted = x509_oid_get_dotted(self_in);
    mp_printf(print, "<ObjectIdentifier(oid=%s, name=%s)>", dotted, x509_oid_name_from_dotted(dotted));
}

static mp_obj_t x509_oid_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_oid_t *o = m_new_obj(mp_x509_oid_t);
    o->base.type = &x509_oid_type;
    o->dotted_string = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static void x509_oid_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_oid_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_dotted_string)
    {
        dest[0] = self->dotted_string;
    }
}

static mp_obj_t x509_oid_binary_op(mp_binary_op_t op, mp_obj_t lhs_in, mp_obj_t rhs_in)
{
    if (op != MP_BINARY_OP_EQUAL && op != MP_BINARY_OP_NOT_EQUAL)
    {
        return MP_OBJ_NULL;
    }
    bool eq = mp_obj_is_type(rhs_in, &x509_oid_type) && strcmp(x509_oid_get_dotted(lhs_in), x509_oid_get_dotted(rhs_in)) == 0;
    return mp_obj_new_bool(op == MP_BINARY_OP_EQUAL ? eq : !eq);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_oid_type,
    MP_QSTR_ObjectIdentifier,
    MP_TYPE_FLAG_NONE,
    make_new, x509_oid_make_new,
    print, x509_oid_print,
    attr, x509_oid_attr,
    binary_op, x509_oid_binary_op);

static void x509_nameoid_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    (void)obj;
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    const char *d = NULL;
    switch (attr)
    {
    case MP_QSTR_COUNTRY_NAME:
        d = "2.5.4.6";
        break;
    case MP_QSTR_STATE_OR_PROVINCE_NAME:
        d = "2.5.4.8";
        break;
    case MP_QSTR_LOCALITY_NAME:
        d = "2.5.4.7";
        break;
    case MP_QSTR_ORGANIZATION_NAME:
        d = "2.5.4.10";
        break;
    case MP_QSTR_ORGANIZATIONAL_UNIT_NAME:
        d = "2.5.4.11";
        break;
    case MP_QSTR_COMMON_NAME:
        d = "2.5.4.3";
        break;
    case MP_QSTR_SERIAL_NUMBER:
        d = "2.5.4.5";
        break;
    case MP_QSTR_EMAIL_ADDRESS:
        d = "1.2.840.113549.1.9.1";
        break;
    case MP_QSTR_DOMAIN_COMPONENT:
        d = "0.9.2342.19200300.100.1.25";
        break;
    default:
        return;
    }
    dest[0] = x509_oid_new(d);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_nameoid_type,
    MP_QSTR_NameOID,
    MP_TYPE_FLAG_NONE,
    attr, x509_nameoid_attr);

static const mp_obj_base_t x509_nameoid_obj = {&x509_nameoid_type};

static void x509_ekuoid_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    (void)obj;
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    const char *d = NULL;
    switch (attr)
    {
    case MP_QSTR_SERVER_AUTH:
        d = "1.3.6.1.5.5.7.3.1";
        break;
    case MP_QSTR_CLIENT_AUTH:
        d = "1.3.6.1.5.5.7.3.2";
        break;
    case MP_QSTR_CODE_SIGNING:
        d = "1.3.6.1.5.5.7.3.3";
        break;
    case MP_QSTR_EMAIL_PROTECTION:
        d = "1.3.6.1.5.5.7.3.4";
        break;
    case MP_QSTR_TIME_STAMPING:
        d = "1.3.6.1.5.5.7.3.8";
        break;
    case MP_QSTR_OCSP_SIGNING:
        d = "1.3.6.1.5.5.7.3.9";
        break;
    default:
        return;
    }
    dest[0] = x509_oid_new(d);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_ekuoid_type,
    MP_QSTR_ExtendedKeyUsageOID,
    MP_TYPE_FLAG_NONE,
    attr, x509_ekuoid_attr);

static const mp_obj_base_t x509_ekuoid_obj = {&x509_ekuoid_type};

static mp_obj_t x509_name_attribute_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 2, 2, false);
    mp_x509_name_attribute_t *o = m_new_obj(mp_x509_name_attribute_t);
    o->base.type = &x509_name_attribute_type;
    o->oid = args[0];
    o->value = args[1];
    return MP_OBJ_FROM_PTR(o);
}

static void x509_name_attribute_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_name_attribute_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_oid)
    {
        dest[0] = self->oid;
    }
    else if (attr == MP_QSTR_value)
    {
        dest[0] = self->value;
    }
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_name_attribute_type,
    MP_QSTR_NameAttribute,
    MP_TYPE_FLAG_NONE,
    make_new, x509_name_attribute_make_new,
    attr, x509_name_attribute_attr);

static mp_obj_t x509_name_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_name_t *o = m_new_obj(mp_x509_name_t);
    o->base.type = &x509_name_type;
    o->attributes = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_name_getiter(mp_obj_t self_in, mp_obj_iter_buf_t *iter_buf)
{
    return mp_getiter(((mp_x509_name_t *)MP_OBJ_TO_PTR(self_in))->attributes, iter_buf);
}

static mp_obj_t x509_name_unary_op(mp_unary_op_t op, mp_obj_t self_in)
{
    if (op == MP_UNARY_OP_LEN)
    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(((mp_x509_name_t *)MP_OBJ_TO_PTR(self_in))->attributes, &n, &items);
        return MP_OBJ_NEW_SMALL_INT(n);
    }
    return MP_OBJ_NULL;
}

static mp_obj_t x509_name_rfc4514_string(mp_obj_t self_in)
{
    mp_x509_name_t *self = MP_OBJ_TO_PTR(self_in);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(self->attributes, &n, &items);
    vstr_t v;
    vstr_init(&v, 32);
    for (size_t i = n; i > 0; i--)
    {
        mp_x509_name_attribute_t *na = MP_OBJ_TO_PTR(items[i - 1]);
        if (i < n)
        {
            vstr_add_byte(&v, ',');
        }
        vstr_add_str(&v, x509_oid_to_name_key(na->oid));
        vstr_add_byte(&v, '=');
        size_t vl;
        const char *s = mp_obj_str_get_data(na->value, &vl);
        for (size_t j = 0; j < vl; j++)
        {
            char ch = s[j];
            if (ch == ',' || ch == '+' || ch == '\\' || ch == '"' || ch == ';' || ch == '<' || ch == '>')
            {
                vstr_add_byte(&v, '\\');
            }
            vstr_add_byte(&v, ch);
        }
    }
    mp_obj_t r = mp_obj_new_str(v.buf, v.len);
    vstr_clear(&v);
    return r;
}
static MP_DEFINE_CONST_FUN_OBJ_1(x509_name_rfc4514_string_obj, x509_name_rfc4514_string);

static mp_obj_t x509_name_get_attributes_for_oid(mp_obj_t self_in, mp_obj_t oid)
{
    mp_x509_name_t *self = MP_OBJ_TO_PTR(self_in);
    const char *want = x509_oid_get_dotted(oid);
    mp_obj_t res = mp_obj_new_list(0, NULL);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(self->attributes, &n, &items);
    for (size_t i = 0; i < n; i++)
    {
        mp_x509_name_attribute_t *na = MP_OBJ_TO_PTR(items[i]);
        if (strcmp(x509_oid_get_dotted(na->oid), want) == 0)
        {
            mp_obj_list_append(res, items[i]);
        }
    }
    return res;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_name_get_attributes_for_oid_obj, x509_name_get_attributes_for_oid);

static void x509_name_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_obj_t s = x509_name_rfc4514_string(self_in);
    mp_printf(print, "<Name(%s)>", mp_obj_str_get_str(s));
}

static const mp_rom_map_elem_t x509_name_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_rfc4514_string), MP_ROM_PTR(&x509_name_rfc4514_string_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_attributes_for_oid), MP_ROM_PTR(&x509_name_get_attributes_for_oid_obj)},
};
static MP_DEFINE_CONST_DICT(x509_name_locals_dict, x509_name_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_name_type,
    MP_QSTR_Name,
    MP_TYPE_FLAG_ITER_IS_GETITER,
    make_new, x509_name_make_new,
    print, x509_name_print,
    iter, x509_name_getiter,
    unary_op, x509_name_unary_op,
    locals_dict, &x509_name_locals_dict);

static mp_obj_t x509_dns_name_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_general_name_t *o = m_new_obj(mp_x509_general_name_t);
    o->base.type = &x509_dns_name_type;
    o->kind = 2;
    o->value = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_ip_address_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_general_name_t *o = m_new_obj(mp_x509_general_name_t);
    o->base.type = &x509_ip_address_type;
    o->kind = 7;
    o->value = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static void x509_general_name_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_general_name_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_value)
    {
        dest[0] = self->value;
    }
}

static void x509_general_name_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_x509_general_name_t *self = MP_OBJ_TO_PTR(self_in);
    mp_print_str(print, self->kind == 2 ? "<DNSName(value=" : "<IPAddress(value=");
    mp_obj_print_helper(print, self->value, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_dns_name_type,
    MP_QSTR_DNSName,
    MP_TYPE_FLAG_NONE,
    make_new, x509_dns_name_make_new,
    print, x509_general_name_print,
    attr, x509_general_name_attr);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_ip_address_type,
    MP_QSTR_IPAddress,
    MP_TYPE_FLAG_NONE,
    make_new, x509_ip_address_make_new,
    print, x509_general_name_print,
    attr, x509_general_name_attr);

static mp_obj_t x509_san_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_san_t *o = m_new_obj(mp_x509_san_t);
    o->base.type = &x509_san_type;
    o->general_names = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_san_getiter(mp_obj_t self_in, mp_obj_iter_buf_t *iter_buf)
{
    return mp_getiter(((mp_x509_san_t *)MP_OBJ_TO_PTR(self_in))->general_names, iter_buf);
}

static mp_obj_t x509_san_unary_op(mp_unary_op_t op, mp_obj_t self_in)
{
    if (op == MP_UNARY_OP_LEN)
    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(((mp_x509_san_t *)MP_OBJ_TO_PTR(self_in))->general_names, &n, &items);
        return MP_OBJ_NEW_SMALL_INT(n);
    }
    return MP_OBJ_NULL;
}

static mp_obj_t x509_san_get_values_for_type(mp_obj_t self_in, mp_obj_t type_in)
{
    mp_x509_san_t *self = MP_OBJ_TO_PTR(self_in);
    const mp_obj_type_t *want = (const mp_obj_type_t *)MP_OBJ_TO_PTR(type_in);
    mp_obj_t res = mp_obj_new_list(0, NULL);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(self->general_names, &n, &items);
    for (size_t i = 0; i < n; i++)
    {
        if (mp_obj_get_type(items[i]) == want)
        {
            mp_obj_list_append(res, ((mp_x509_general_name_t *)MP_OBJ_TO_PTR(items[i]))->value);
        }
    }
    return res;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_san_get_values_for_type_obj, x509_san_get_values_for_type);

static const mp_rom_map_elem_t x509_san_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_get_values_for_type), MP_ROM_PTR(&x509_san_get_values_for_type_obj)},
};
static MP_DEFINE_CONST_DICT(x509_san_locals_dict, x509_san_locals_dict_table);

static void x509_san_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_print_str(print, "<SubjectAlternativeName(");
    mp_obj_print_helper(print, ((mp_x509_san_t *)MP_OBJ_TO_PTR(self_in))->general_names, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_san_type,
    MP_QSTR_SubjectAlternativeName,
    MP_TYPE_FLAG_ITER_IS_GETITER,
    make_new, x509_san_make_new,
    print, x509_san_print,
    iter, x509_san_getiter,
    unary_op, x509_san_unary_op,
    locals_dict, &x509_san_locals_dict);

static mp_obj_t x509_basic_constraints_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
    enum
    {
        ARG_ca,
        ARG_path_length
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_ca, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_path_length, MP_ARG_OBJ, {.u_obj = mp_const_none}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    mp_x509_basic_constraints_t *o = m_new_obj(mp_x509_basic_constraints_t);
    o->base.type = &x509_basic_constraints_type;
    o->ca = mp_obj_is_true(args[ARG_ca].u_obj);
    o->path_length = args[ARG_path_length].u_obj;
    return MP_OBJ_FROM_PTR(o);
}

static void x509_basic_constraints_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_basic_constraints_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_ca)
    {
        dest[0] = mp_obj_new_bool(self->ca);
    }
    else if (attr == MP_QSTR_path_length)
    {
        dest[0] = self->path_length;
    }
}

static void x509_basic_constraints_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_x509_basic_constraints_t *self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "<BasicConstraints(ca=%s, path_length=", self->ca ? "True" : "False");
    mp_obj_print_helper(print, self->path_length, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_basic_constraints_type,
    MP_QSTR_BasicConstraints,
    MP_TYPE_FLAG_NONE,
    make_new, x509_basic_constraints_make_new,
    print, x509_basic_constraints_print,
    attr, x509_basic_constraints_attr);

static mp_obj_t x509_key_usage_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
    enum
    {
        ARG_digital_signature,
        ARG_content_commitment,
        ARG_key_encipherment,
        ARG_data_encipherment,
        ARG_key_agreement,
        ARG_key_cert_sign,
        ARG_crl_sign,
        ARG_encipher_only,
        ARG_decipher_only
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_digital_signature, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_content_commitment, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_key_encipherment, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_data_encipherment, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_key_agreement, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_key_cert_sign, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_crl_sign, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encipher_only, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_decipher_only, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    mp_x509_key_usage_t *o = m_new_obj(mp_x509_key_usage_t);
    o->base.type = &x509_key_usage_type;
    unsigned int f = 0;
    if (mp_obj_is_true(args[ARG_digital_signature].u_obj))
    {
        f |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    }
    if (mp_obj_is_true(args[ARG_content_commitment].u_obj))
    {
        f |= MBEDTLS_X509_KU_NON_REPUDIATION;
    }
    if (mp_obj_is_true(args[ARG_key_encipherment].u_obj))
    {
        f |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
    }
    if (mp_obj_is_true(args[ARG_data_encipherment].u_obj))
    {
        f |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
    }
    if (mp_obj_is_true(args[ARG_key_agreement].u_obj))
    {
        f |= MBEDTLS_X509_KU_KEY_AGREEMENT;
    }
    if (mp_obj_is_true(args[ARG_key_cert_sign].u_obj))
    {
        f |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
    }
    if (mp_obj_is_true(args[ARG_crl_sign].u_obj))
    {
        f |= MBEDTLS_X509_KU_CRL_SIGN;
    }
    if (mp_obj_is_true(args[ARG_encipher_only].u_obj))
    {
        f |= MBEDTLS_X509_KU_ENCIPHER_ONLY;
    }
    if (mp_obj_is_true(args[ARG_decipher_only].u_obj))
    {
        f |= MBEDTLS_X509_KU_DECIPHER_ONLY;
    }
    o->flags = f;
    return MP_OBJ_FROM_PTR(o);
}

static void x509_key_usage_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_key_usage_t *self = MP_OBJ_TO_PTR(obj);
    unsigned int f = self->flags;
    if (attr == MP_QSTR_digital_signature)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    else if (attr == MP_QSTR_content_commitment)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_NON_REPUDIATION);
    else if (attr == MP_QSTR_key_encipherment)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    else if (attr == MP_QSTR_data_encipherment)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_DATA_ENCIPHERMENT);
    else if (attr == MP_QSTR_key_agreement)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_KEY_AGREEMENT);
    else if (attr == MP_QSTR_key_cert_sign)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_KEY_CERT_SIGN);
    else if (attr == MP_QSTR_crl_sign)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_CRL_SIGN);
    else if (attr == MP_QSTR_encipher_only)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_ENCIPHER_ONLY);
    else if (attr == MP_QSTR_decipher_only)
        dest[0] = mp_obj_new_bool(f & MBEDTLS_X509_KU_DECIPHER_ONLY);
}

static void x509_key_usage_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    unsigned int f = ((mp_x509_key_usage_t *)MP_OBJ_TO_PTR(self_in))->flags;
    bool ka = (f & MBEDTLS_X509_KU_KEY_AGREEMENT) != 0;
    mp_printf(print,
              "<KeyUsage(digital_signature=%s, content_commitment=%s, key_encipherment=%s, data_encipherment=%s, key_agreement=%s, key_cert_sign=%s, crl_sign=%s, encipher_only=%s, decipher_only=%s)>",
              (f & MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ? "True" : "False",
              (f & MBEDTLS_X509_KU_NON_REPUDIATION) ? "True" : "False",
              (f & MBEDTLS_X509_KU_KEY_ENCIPHERMENT) ? "True" : "False",
              (f & MBEDTLS_X509_KU_DATA_ENCIPHERMENT) ? "True" : "False",
              (f & MBEDTLS_X509_KU_KEY_AGREEMENT) ? "True" : "False",
              (f & MBEDTLS_X509_KU_KEY_CERT_SIGN) ? "True" : "False",
              (f & MBEDTLS_X509_KU_CRL_SIGN) ? "True" : "False",
              ka ? ((f & MBEDTLS_X509_KU_ENCIPHER_ONLY) ? "True" : "False") : "None",
              ka ? ((f & MBEDTLS_X509_KU_DECIPHER_ONLY) ? "True" : "False") : "None");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_key_usage_type,
    MP_QSTR_KeyUsage,
    MP_TYPE_FLAG_NONE,
    make_new, x509_key_usage_make_new,
    print, x509_key_usage_print,
    attr, x509_key_usage_attr);

static mp_obj_t x509_ext_key_usage_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_x509_ext_key_usage_t *o = m_new_obj(mp_x509_ext_key_usage_t);
    o->base.type = &x509_ext_key_usage_type;
    o->usages = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_ext_key_usage_getiter(mp_obj_t self_in, mp_obj_iter_buf_t *iter_buf)
{
    return mp_getiter(((mp_x509_ext_key_usage_t *)MP_OBJ_TO_PTR(self_in))->usages, iter_buf);
}

static mp_obj_t x509_ext_key_usage_unary_op(mp_unary_op_t op, mp_obj_t self_in)
{
    if (op == MP_UNARY_OP_LEN)
    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(((mp_x509_ext_key_usage_t *)MP_OBJ_TO_PTR(self_in))->usages, &n, &items);
        return MP_OBJ_NEW_SMALL_INT(n);
    }
    return MP_OBJ_NULL;
}

static void x509_ext_key_usage_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_print_str(print, "<ExtendedKeyUsage(");
    mp_obj_print_helper(print, ((mp_x509_ext_key_usage_t *)MP_OBJ_TO_PTR(self_in))->usages, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_ext_key_usage_type,
    MP_QSTR_ExtendedKeyUsage,
    MP_TYPE_FLAG_ITER_IS_GETITER,
    make_new, x509_ext_key_usage_make_new,
    print, x509_ext_key_usage_print,
    iter, x509_ext_key_usage_getiter,
    unary_op, x509_ext_key_usage_unary_op);

static mp_obj_t x509_ski_new(void)
{
    mp_x509_ski_t *o = m_new_obj(mp_x509_ski_t);
    o->base.type = &x509_ski_type;
    o->digest = mp_const_none;
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_ski_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    (void)args;
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    return x509_ski_new();
}

static mp_obj_t x509_ski_from_public_key(mp_obj_t public_key)
{
    (void)public_key;
    return x509_ski_new();
}

static MP_DEFINE_CONST_FUN_OBJ_1(x509_ski_from_public_key_obj, x509_ski_from_public_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(x509_static_ski_from_public_key_obj, MP_ROM_PTR(&x509_ski_from_public_key_obj));

static const mp_rom_map_elem_t x509_ski_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_from_public_key), MP_ROM_PTR(&x509_static_ski_from_public_key_obj)},
};
static MP_DEFINE_CONST_DICT(x509_ski_locals_dict, x509_ski_locals_dict_table);

static void x509_ski_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_ski_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_digest || attr == MP_QSTR_key_identifier)
    {
        dest[0] = self->digest;
    }
}

static void x509_ski_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_print_str(print, "<SubjectKeyIdentifier(digest=");
    mp_obj_print_helper(print, ((mp_x509_ski_t *)MP_OBJ_TO_PTR(self_in))->digest, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_ski_type,
    MP_QSTR_SubjectKeyIdentifier,
    MP_TYPE_FLAG_NONE,
    make_new, x509_ski_make_new,
    print, x509_ski_print,
    attr, x509_ski_attr,
    locals_dict, &x509_ski_locals_dict);

static mp_obj_t x509_aki_new(void)
{
    mp_x509_aki_t *o = m_new_obj(mp_x509_aki_t);
    o->base.type = &x509_aki_type;
    o->key_identifier = mp_const_none;
    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t x509_aki_from_issuer_subject_key_identifier(mp_obj_t ski)
{
    (void)ski;
    return x509_aki_new();
}

static mp_obj_t x509_aki_from_issuer_public_key(mp_obj_t public_key)
{
    (void)public_key;
    return x509_aki_new();
}

static MP_DEFINE_CONST_FUN_OBJ_1(x509_aki_from_issuer_subject_key_identifier_obj, x509_aki_from_issuer_subject_key_identifier);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(x509_static_aki_from_issuer_ski_obj, MP_ROM_PTR(&x509_aki_from_issuer_subject_key_identifier_obj));
static MP_DEFINE_CONST_FUN_OBJ_1(x509_aki_from_issuer_public_key_obj, x509_aki_from_issuer_public_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(x509_static_aki_from_issuer_pk_obj, MP_ROM_PTR(&x509_aki_from_issuer_public_key_obj));

static const mp_rom_map_elem_t x509_aki_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_from_issuer_subject_key_identifier), MP_ROM_PTR(&x509_static_aki_from_issuer_ski_obj)},
    {MP_ROM_QSTR(MP_QSTR_from_issuer_public_key), MP_ROM_PTR(&x509_static_aki_from_issuer_pk_obj)},
};
static MP_DEFINE_CONST_DICT(x509_aki_locals_dict, x509_aki_locals_dict_table);

static void x509_aki_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_aki_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_key_identifier)
    {
        dest[0] = self->key_identifier;
    }
}

static void x509_aki_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_print_str(print, "<AuthorityKeyIdentifier(key_identifier=");
    mp_obj_print_helper(print, ((mp_x509_aki_t *)MP_OBJ_TO_PTR(self_in))->key_identifier, PRINT_REPR);
    mp_print_str(print, ", authority_cert_issuer=None, authority_cert_serial_number=None)>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_aki_type,
    MP_QSTR_AuthorityKeyIdentifier,
    MP_TYPE_FLAG_NONE,
    print, x509_aki_print,
    attr, x509_aki_attr,
    locals_dict, &x509_aki_locals_dict);

static mp_obj_t x509_unrecognized_extension_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 2, 2, false);
    mp_x509_unrecognized_extension_t *o = m_new_obj(mp_x509_unrecognized_extension_t);
    o->base.type = &x509_unrecognized_extension_type;
    o->oid = args[0];
    o->value = args[1];
    return MP_OBJ_FROM_PTR(o);
}

static void x509_unrecognized_extension_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_unrecognized_extension_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_oid)
    {
        dest[0] = self->oid;
    }
    else if (attr == MP_QSTR_value)
    {
        dest[0] = self->value;
    }
}

static void x509_unrecognized_extension_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_x509_unrecognized_extension_t *self = MP_OBJ_TO_PTR(self_in);
    mp_print_str(print, "<UnrecognizedExtension(oid=");
    mp_obj_print_helper(print, self->oid, PRINT_REPR);
    mp_print_str(print, ", value=");
    mp_obj_print_helper(print, self->value, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_unrecognized_extension_type,
    MP_QSTR_UnrecognizedExtension,
    MP_TYPE_FLAG_NONE,
    make_new, x509_unrecognized_extension_make_new,
    print, x509_unrecognized_extension_print,
    attr, x509_unrecognized_extension_attr);

#if MICROPY_PY_UCRYPTOGRAPHY_X509
static void x509_extension_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    if (dest[0] != MP_OBJ_NULL)
    {
        return;
    }
    mp_x509_extension_t *self = MP_OBJ_TO_PTR(obj);
    if (attr == MP_QSTR_oid)
        dest[0] = self->oid;
    else if (attr == MP_QSTR_critical)
        dest[0] = self->critical;
    else if (attr == MP_QSTR_value)
        dest[0] = self->value;
}

static void x509_extension_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_x509_extension_t *self = MP_OBJ_TO_PTR(self_in);
    mp_print_str(print, "<Extension(oid=");
    mp_obj_print_helper(print, self->oid, PRINT_REPR);
    mp_print_str(print, ", critical=");
    mp_obj_print_helper(print, self->critical, PRINT_REPR);
    mp_print_str(print, ", value=");
    mp_obj_print_helper(print, self->value, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_extension_type,
    MP_QSTR_Extension,
    MP_TYPE_FLAG_NONE,
    print, x509_extension_print,
    attr, x509_extension_attr);

static mp_obj_t x509_extensions_getiter(mp_obj_t self_in, mp_obj_iter_buf_t *iter_buf)
{
    return mp_getiter(((mp_x509_extensions_t *)MP_OBJ_TO_PTR(self_in))->list, iter_buf);
}

static mp_obj_t x509_extensions_unary_op(mp_unary_op_t op, mp_obj_t self_in)
{
    if (op == MP_UNARY_OP_LEN)
    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(((mp_x509_extensions_t *)MP_OBJ_TO_PTR(self_in))->list, &n, &items);
        return MP_OBJ_NEW_SMALL_INT(n);
    }
    return MP_OBJ_NULL;
}

static mp_obj_t x509_extensions_get_extension_for_oid(mp_obj_t self_in, mp_obj_t oid)
{
    mp_x509_extensions_t *self = MP_OBJ_TO_PTR(self_in);
    const char *want = x509_oid_get_dotted(oid);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(self->list, &n, &items);
    for (size_t i = 0; i < n; i++)
    {
        mp_x509_extension_t *e = MP_OBJ_TO_PTR(items[i]);
        if (strcmp(x509_oid_get_dotted(e->oid), want) == 0)
        {
            return items[i];
        }
    }
    mp_raise_ValueError(MP_ERROR_TEXT("ExtensionNotFound"));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_extensions_get_extension_for_oid_obj, x509_extensions_get_extension_for_oid);

static mp_obj_t x509_extensions_get_extension_for_class(mp_obj_t self_in, mp_obj_t cls)
{
    mp_x509_extensions_t *self = MP_OBJ_TO_PTR(self_in);
    const mp_obj_type_t *want = (const mp_obj_type_t *)MP_OBJ_TO_PTR(cls);
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(self->list, &n, &items);
    for (size_t i = 0; i < n; i++)
    {
        mp_x509_extension_t *e = MP_OBJ_TO_PTR(items[i]);
        if (mp_obj_get_type(e->value) == want)
        {
            return items[i];
        }
    }
    mp_raise_ValueError(MP_ERROR_TEXT("ExtensionNotFound"));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_extensions_get_extension_for_class_obj, x509_extensions_get_extension_for_class);

static const mp_rom_map_elem_t x509_extensions_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_get_extension_for_oid), MP_ROM_PTR(&x509_extensions_get_extension_for_oid_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_extension_for_class), MP_ROM_PTR(&x509_extensions_get_extension_for_class_obj)},
};
static MP_DEFINE_CONST_DICT(x509_extensions_locals_dict, x509_extensions_locals_dict_table);

static void x509_extensions_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_print_str(print, "<Extensions(");
    mp_obj_print_helper(print, ((mp_x509_extensions_t *)MP_OBJ_TO_PTR(self_in))->list, PRINT_REPR);
    mp_print_str(print, ")>");
}

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_extensions_type,
    MP_QSTR_Extensions,
    MP_TYPE_FLAG_ITER_IS_GETITER,
    print, x509_extensions_print,
    iter, x509_extensions_getiter,
    unary_op, x509_extensions_unary_op,
    locals_dict, &x509_extensions_locals_dict);
#endif

static mp_obj_t x509_cert_builder_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 create disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE)"));
#else
    (void)args;
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_x509_cert_builder_t *o = m_new_obj(mp_x509_cert_builder_t);
    o->base.type = &x509_cert_builder_type;
    o->subject_name = MP_OBJ_NULL;
    o->issuer_name = MP_OBJ_NULL;
    o->public_key = MP_OBJ_NULL;
    o->serial_number = MP_OBJ_NULL;
    o->not_valid_before = MP_OBJ_NULL;
    o->not_valid_after = MP_OBJ_NULL;
    o->extensions = mp_obj_new_list(0, NULL);
    return MP_OBJ_FROM_PTR(o);
#endif
}

static mp_obj_t x509_cert_builder_subject_name(mp_obj_t self_in, mp_obj_t name)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->subject_name = name;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_subject_name_obj, x509_cert_builder_subject_name);

static mp_obj_t x509_cert_builder_issuer_name(mp_obj_t self_in, mp_obj_t name)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->issuer_name = name;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_issuer_name_obj, x509_cert_builder_issuer_name);

static mp_obj_t x509_cert_builder_public_key(mp_obj_t self_in, mp_obj_t key)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->public_key = key;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_public_key_obj, x509_cert_builder_public_key);

static mp_obj_t x509_cert_builder_serial_number(mp_obj_t self_in, mp_obj_t serial)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->serial_number = serial;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_serial_number_obj, x509_cert_builder_serial_number);

static mp_obj_t x509_cert_builder_not_valid_before(mp_obj_t self_in, mp_obj_t when)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->not_valid_before = when;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_not_valid_before_obj, x509_cert_builder_not_valid_before);

static mp_obj_t x509_cert_builder_not_valid_after(mp_obj_t self_in, mp_obj_t when)
{
    ((mp_x509_cert_builder_t *)MP_OBJ_TO_PTR(self_in))->not_valid_after = when;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_cert_builder_not_valid_after_obj, x509_cert_builder_not_valid_after);

static mp_obj_t x509_cert_builder_add_extension(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args)
{
    mp_x509_cert_builder_t *self = MP_OBJ_TO_PTR(pos_args[0]);
    enum
    {
        ARG_extension,
        ARG_critical
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_extension, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_critical, MP_ARG_OBJ, {.u_obj = mp_const_false}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    mp_obj_t tup[2] = {args[ARG_extension].u_obj, mp_obj_new_bool(mp_obj_is_true(args[ARG_critical].u_obj))};
    mp_obj_list_append(self->extensions, mp_obj_new_tuple(2, tup));
    return pos_args[0];
}
static MP_DEFINE_CONST_FUN_OBJ_KW(x509_cert_builder_add_extension_obj, 2, x509_cert_builder_add_extension);

static mp_obj_t x509_cert_builder_sign(mp_obj_t self_in, mp_obj_t private_key, mp_obj_t algorithm)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE
    (void)self_in;
    (void)private_key;
    (void)algorithm;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 create disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE)"));
#else
    mp_x509_cert_builder_t *self = MP_OBJ_TO_PTR(self_in);
    if (self->subject_name == MP_OBJ_NULL || self->issuer_name == MP_OBJ_NULL || self->public_key == MP_OBJ_NULL || self->serial_number == MP_OBJ_NULL || self->not_valid_before == MP_OBJ_NULL || self->not_valid_after == MP_OBJ_NULL)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Builder is missing required fields"));
    }

    mbedtls_md_type_t md = x509_hash_to_md(algorithm);

    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_context subject_pk;
    mbedtls_pk_init(&subject_pk);
    mbedtls_pk_context issuer_pk;
    mbedtls_pk_init(&issuer_pk);

    int ret = 0;
    mp_obj_t result = mp_const_none;

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, md);

    vstr_t vstr_subject;
    vstr_init(&vstr_subject, 64);
    x509_name_to_string(self->subject_name, &vstr_subject);
    ret = mbedtls_x509write_crt_set_subject_name(&crt, vstr_null_terminated_str(&vstr_subject));
    vstr_clear(&vstr_subject);
    if (ret != 0)
    {
        goto cleanup;
    }

    vstr_t vstr_issuer;
    vstr_init(&vstr_issuer, 64);
    x509_name_to_string(self->issuer_name, &vstr_issuer);
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, vstr_null_terminated_str(&vstr_issuer));
    vstr_clear(&vstr_issuer);
    if (ret != 0)
    {
        goto cleanup;
    }

    crypto_pk_from_public_key(&subject_pk, self->public_key);
    crypto_pk_from_private_key(&issuer_pk, private_key);
    mbedtls_x509write_crt_set_subject_key(&crt, &subject_pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_pk);

    {
        mbedtls_mpi serial;
        mbedtls_mpi_init(&serial);
        mbedtls_mpi_read_binary_from_mp_obj(&serial, self->serial_number, true);
        size_t serial_len = mbedtls_mpi_size(&serial);
        if (serial_len == 0)
        {
            serial_len = 1;
        }
        unsigned char serial_raw[32];
        if (serial_len > sizeof(serial_raw))
        {
            serial_len = sizeof(serial_raw);
        }
        ret = mbedtls_mpi_write_binary(&serial, serial_raw, serial_len);
        mbedtls_mpi_free(&serial);
        if (ret != 0)
        {
            goto cleanup;
        }
        if ((serial_raw[0] & 0x80) && serial_len < MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN)
        {
            unsigned char tmp[33];
            tmp[0] = 0x00;
            memcpy(tmp + 1, serial_raw, serial_len);
            ret = mbedtls_x509write_crt_set_serial_raw(&crt, tmp, serial_len + 1);
        }
        else
        {
            ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial_raw, serial_len);
        }
        if (ret != 0)
        {
            goto cleanup;
        }
    }

    {
        vstr_t vstr_nb;
        vstr_init(&vstr_nb, 15);
        vstr_t vstr_na;
        vstr_init(&vstr_na, 15);
        x509_datetime_to_string(self->not_valid_before, &vstr_nb);
        x509_datetime_to_string(self->not_valid_after, &vstr_na);
        ret = mbedtls_x509write_crt_set_validity(&crt, vstr_null_terminated_str(&vstr_nb), vstr_null_terminated_str(&vstr_na));
        vstr_clear(&vstr_nb);
        vstr_clear(&vstr_na);
        if (ret != 0)
        {
            goto cleanup;
        }
    }

    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(self->extensions, &n, &items);
        for (size_t i = 0; i < n; i++)
        {
            mp_obj_t *pair;
            size_t plen;
            mp_obj_get_array(items[i], &plen, &pair);
            ret = x509_apply_extension(&crt, false, pair[0], mp_obj_is_true(pair[1]));
            if (ret != 0)
            {
                goto cleanup;
            }
        }
    }

    {
        size_t bufsize = 4096;
        byte *buf = m_new(byte, bufsize);
        int wr = mbedtls_x509write_crt_der(&crt, buf, bufsize, mp_random, NULL);
        if (wr < 0)
        {
            m_del(byte, buf, bufsize);
            ret = wr;
            goto cleanup;
        }
        mp_obj_t der = mp_obj_new_bytes(buf + bufsize - wr, wr);
        m_del(byte, buf, bufsize);
        result = x509_crt_parse_der(der);
    }

cleanup:
    mbedtls_pk_free(&subject_pk);
    mbedtls_pk_free(&issuer_pk);
    mbedtls_x509write_crt_free(&crt);
    if (result == mp_const_none)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Certificate signing failed"));
    }
    return result;
#endif
}
static MP_DEFINE_CONST_FUN_OBJ_3(x509_cert_builder_sign_obj, x509_cert_builder_sign);

static const mp_rom_map_elem_t x509_cert_builder_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_subject_name), MP_ROM_PTR(&x509_cert_builder_subject_name_obj)},
    {MP_ROM_QSTR(MP_QSTR_issuer_name), MP_ROM_PTR(&x509_cert_builder_issuer_name_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&x509_cert_builder_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_serial_number), MP_ROM_PTR(&x509_cert_builder_serial_number_obj)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_before), MP_ROM_PTR(&x509_cert_builder_not_valid_before_obj)},
    {MP_ROM_QSTR(MP_QSTR_not_valid_after), MP_ROM_PTR(&x509_cert_builder_not_valid_after_obj)},
    {MP_ROM_QSTR(MP_QSTR_add_extension), MP_ROM_PTR(&x509_cert_builder_add_extension_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&x509_cert_builder_sign_obj)},
};
static MP_DEFINE_CONST_DICT(x509_cert_builder_locals_dict, x509_cert_builder_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_cert_builder_type,
    MP_QSTR_CertificateBuilder,
    MP_TYPE_FLAG_NONE,
    make_new, x509_cert_builder_make_new,
    locals_dict, &x509_cert_builder_locals_dict);

static mp_obj_t x509_random_serial_number(void)
{
    byte buf[20];
    mp_random(NULL, buf, sizeof(buf));
    buf[0] &= 0x7F;
    if (buf[0] == 0x00)
    {
        buf[0] = 0x01;
    }
    return mp_obj_int_from_bytes_impl(true, sizeof(buf), buf);
}
static MP_DEFINE_CONST_FUN_OBJ_0(x509_random_serial_number_obj, x509_random_serial_number);

static mp_obj_t x509_crt_parse_pem(mp_obj_t certificate)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_X509
    (void)certificate;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509)"));
#else
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(certificate, &bufinfo, MP_BUFFER_READ);
    size_t inlen = bufinfo.len;
    byte *pembuf = m_new(byte, inlen + 1);
    memcpy(pembuf, bufinfo.buf, inlen);
    pembuf[inlen] = '\0';
    mbedtls_pem_context pem;
    mbedtls_pem_init(&pem);
    size_t use_len = 0;
    int ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pembuf, NULL, 0, &use_len);
    m_del(byte, pembuf, inlen + 1);
    if (ret != 0)
    {
        mbedtls_pem_free(&pem);
        mp_raise_ValueError(MP_ERROR_TEXT("Certificate format"));
    }
    size_t der_len = 0;
    const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &der_len);
    mp_obj_t der = mp_obj_new_bytes(der_buf, der_len);
    mbedtls_pem_free(&pem);
    return x509_crt_parse_der(der);
#endif
}
static MP_DEFINE_CONST_FUN_OBJ_1(x509_crt_parse_pem_obj, x509_crt_parse_pem);

// ===== X.509 Certificate Signing Request (CSR), PyCA cryptography-compatible =====

static const mp_obj_type_t x509_csr_type;
static const mp_obj_type_t x509_csr_builder_type;

static mp_obj_t x509_csr_public_key(mp_obj_t obj)
{
    mp_x509_csr_t *self = MP_OBJ_TO_PTR(obj);
    if (self->ec_public_key != NULL)
    {
        return self->ec_public_key;
    }
    else if (self->rsa_public_key != NULL)
    {
        return self->rsa_public_key;
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_csr_public_key_obj, x509_csr_public_key);

static mp_obj_t x509_csr_public_bytes(size_t n_args, const mp_obj_t *args)
{
    mp_x509_csr_t *self = MP_OBJ_TO_PTR(args[0]);
    mp_int_t encoding = SERIALIZATION_ENCODING_DER;
    if (n_args == 2)
    {
        encoding = mp_obj_get_int(args[1]);
    }
    if (encoding == SERIALIZATION_ENCODING_DER)
    {
        return self->public_bytes;
    }
    else if (encoding == SERIALIZATION_ENCODING_PEM)
    {
        mp_buffer_info_t der;
        mp_get_buffer_raise(self->public_bytes, &der, MP_BUFFER_READ);
        size_t olen = 0;
        mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n", (const byte *)der.buf, der.len, NULL, 0, &olen);
        vstr_t vstr_pem;
        vstr_init_len(&vstr_pem, olen);
        int ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n", (const byte *)der.buf, der.len, (byte *)vstr_pem.buf, olen, &olen);
        if (ret != 0)
        {
            vstr_clear(&vstr_pem);
            mp_raise_ValueError(MP_ERROR_TEXT("PEM encoding failed"));
        }
        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_pem.buf, olen > 0 ? olen - 1 : 0);
        vstr_clear(&vstr_pem);
        return oo;
    }
    mp_raise_ValueError(MP_ERROR_TEXT("Expected encoding value 1 (DER) or 2 (PEM)"));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_x509_csr_public_bytes_obj, 1, 2, x509_csr_public_bytes);

static void x509_csr_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_x509_csr_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_subject)
            {
                dest[0] = self->subject;
                return;
            }
            if (attr == MP_QSTR_signature)
            {
                dest[0] = self->signature;
                return;
            }
            if (attr == MP_QSTR_signature_algorithm_oid)
            {
                dest[0] = self->signature_algorithm_oid;
                return;
            }
            if (attr == MP_QSTR_signature_hash_algorithm)
            {
                dest[0] = self->signature_hash_algorithm;
                return;
            }
            if (attr == MP_QSTR_extensions)
            {
                dest[0] = self->extensions;
                return;
            }
            if (attr == MP_QSTR_tbs_certrequest_bytes)
            {
                dest[0] = self->tbs_certrequest_bytes;
                return;
            }
            if (attr == MP_QSTR_is_signature_valid)
            {
                dest[0] = self->is_signature_valid;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t x509_csr_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_x509_csr_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_x509_csr_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_subject), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature_algorithm_oid), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_signature_hash_algorithm), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_extensions), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_tbs_certrequest_bytes), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_is_signature_valid), MP_ROM_PTR(mp_const_none)},
};
static MP_DEFINE_CONST_DICT(x509_csr_locals_dict, x509_csr_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_csr_type,
    MP_QSTR_CertificateSigningRequest,
    MP_TYPE_FLAG_NONE,
    attr, x509_csr_attr,
    locals_dict, &x509_csr_locals_dict);

#if MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
// mbedtls only invokes this callback for extensions whose OID it does not know,
// so it always yields an UnrecognizedExtension (KeyUsage/SAN come from the parsed
// fields; BasicConstraints/ExtendedKeyUsage are recovered from csr.cri below).
static int x509_csr_ext_cb(void *p_ctx, const mbedtls_x509_csr *csr, const mbedtls_x509_buf *oid, int critical, const unsigned char *p, const unsigned char *end)
{
    (void)csr;
    mp_x509_csr_ext_ctx_t *ctx = (mp_x509_csr_ext_ctx_t *)p_ctx;
    mp_obj_t oid_obj = x509_new_oid_from_str(x509_crt_parse_oid(oid, &mp_type_str));
    mp_x509_unrecognized_extension_t *ue = m_new_obj(mp_x509_unrecognized_extension_t);
    ue->base.type = &x509_unrecognized_extension_type;
    ue->oid = oid_obj;
    ue->value = mp_obj_new_bytes(p, (size_t)(end - p));
    mp_obj_list_append(ctx->list, x509_new_extension(oid_obj, critical, MP_OBJ_FROM_PTR(ue)));
    return 0;
}

// Navigate the raw CertificationRequestInfo to the extensionRequest attribute's
// Extensions SEQUENCE content. Returns 0 and sets *out_p/*out_end on success,
// 1 if there is no extensionRequest attribute, or a negative value on error.
static int x509_csr_locate_extensions(const mbedtls_x509_buf *cri, unsigned char **out_p, const unsigned char **out_end)
{
    unsigned char *p = cri->p;
    const unsigned char *end = cri->p + cri->len;
    size_t len;
    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        return -1;
    }
    end = p + len;
    int version = 0;
    if (mbedtls_asn1_get_int(&p, end, &version) != 0)
    {
        return -1;
    }
    // subject Name (SEQUENCE) and subjectPKInfo (SEQUENCE): skip both.
    for (int i = 0; i < 2; i++)
    {
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            return -1;
        }
        p += len;
    }
    // attributes [0] IMPLICIT SET OF Attribute
    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0) != 0)
    {
        return 1;
    }
    const unsigned char *attrs_end = p + len;
    while (p < attrs_end)
    {
        if (mbedtls_asn1_get_tag(&p, attrs_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            return -1;
        }
        unsigned char *attr_end = p + len;
        size_t oid_len;
        if (mbedtls_asn1_get_tag(&p, attr_end, &oid_len, MBEDTLS_ASN1_OID) != 0)
        {
            return -1;
        }
        bool is_ext_req = (oid_len == MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ)) && (memcmp(p, MBEDTLS_OID_PKCS9_CSR_EXT_REQ, oid_len) == 0);
        p += oid_len;
        if (is_ext_req)
        {
            if (mbedtls_asn1_get_tag(&p, attr_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0)
            {
                return -1;
            }
            if (mbedtls_asn1_get_tag(&p, attr_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
            {
                return -1;
            }
            *out_p = p;
            *out_end = p + len;
            return 0;
        }
        p = attr_end;
    }
    return 1;
}

// Append BasicConstraints / ExtendedKeyUsage from the CSR's requested extensions.
// mbedtls drops these known-but-CSR-unhandled extensions (KeyUsage/SAN/custom are
// handled elsewhere). Critical requested BasicConstraints/EKU are rejected by
// mbedtls before this runs, so any recovered here are non-critical.
static void x509_csr_append_bc_eku(mp_obj_t list, const mbedtls_x509_buf *cri)
{
    unsigned char *p;
    const unsigned char *end;
    if (x509_csr_locate_extensions(cri, &p, &end) != 0)
    {
        return;
    }
    while (p < end)
    {
        size_t len;
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            break;
        }
        unsigned char *ext_end = p + len;
        mbedtls_x509_buf ob;
        memset(&ob, 0, sizeof(ob));
        if (mbedtls_asn1_get_tag(&p, ext_end, &ob.len, MBEDTLS_ASN1_OID) != 0)
        {
            break;
        }
        ob.tag = MBEDTLS_ASN1_OID;
        ob.p = p;
        p += ob.len;
        int critical = 0;
        int r = mbedtls_asn1_get_bool(&p, ext_end, &critical);
        if (r != 0 && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
        {
            break;
        }
        size_t vlen;
        if (mbedtls_asn1_get_tag(&p, ext_end, &vlen, MBEDTLS_ASN1_OCTET_STRING) != 0)
        {
            break;
        }
        unsigned char *vp = p;
        const unsigned char *vend = p + vlen;
        p = ext_end;
        mp_obj_t oid_obj = x509_new_oid_from_str(x509_crt_parse_oid(&ob, &mp_type_str));
        const char *dotted = x509_oid_get_dotted(oid_obj);
        if (strcmp(dotted, "2.5.29.19") == 0)
        {
            unsigned char *q = vp;
            size_t l;
            bool ca = false;
            mp_obj_t pathlen = mp_const_none;
            if (mbedtls_asn1_get_tag(&q, vend, &l, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0)
            {
                const unsigned char *se = q + l;
                int b = 0;
                if (q < se && mbedtls_asn1_get_bool(&q, se, &b) == 0)
                {
                    ca = b ? true : false;
                }
                if (q < se)
                {
                    int iv = 0;
                    if (mbedtls_asn1_get_int(&q, se, &iv) == 0)
                    {
                        pathlen = mp_obj_new_int(iv);
                    }
                }
            }
            mp_x509_basic_constraints_t *bc = m_new_obj(mp_x509_basic_constraints_t);
            bc->base.type = &x509_basic_constraints_type;
            bc->ca = ca;
            bc->path_length = pathlen;
            mp_obj_list_append(list, x509_new_extension(oid_obj, critical, MP_OBJ_FROM_PTR(bc)));
        }
        else if (strcmp(dotted, "2.5.29.37") == 0)
        {
            unsigned char *q = vp;
            size_t l;
            mp_obj_t usages = mp_obj_new_list(0, NULL);
            if (mbedtls_asn1_get_tag(&q, vend, &l, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0)
            {
                const unsigned char *se = q + l;
                while (q < se)
                {
                    size_t ol;
                    if (mbedtls_asn1_get_tag(&q, se, &ol, MBEDTLS_ASN1_OID) != 0)
                    {
                        break;
                    }
                    mbedtls_x509_buf eo;
                    eo.tag = MBEDTLS_ASN1_OID;
                    eo.len = ol;
                    eo.p = q;
                    mp_obj_list_append(usages, x509_new_oid_from_str(x509_crt_parse_oid(&eo, &mp_type_str)));
                    q += ol;
                }
            }
            mp_x509_ext_key_usage_t *eku = m_new_obj(mp_x509_ext_key_usage_t);
            eku->base.type = &x509_ext_key_usage_type;
            eku->usages = usages;
            mp_obj_list_append(list, x509_new_extension(oid_obj, critical, MP_OBJ_FROM_PTR(eku)));
        }
    }
}
#endif

static mp_obj_t x509_csr_parse_der(mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
    (void)data;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 csr disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CSR)"));
#else
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    mbedtls_x509_csr csr;
    mbedtls_x509_csr_init(&csr);
    mp_x509_csr_ext_ctx_t ectx;
    ectx.list = mp_obj_new_list(0, NULL);
    if (mbedtls_x509_csr_parse_der_with_ext_cb(&csr, (const byte *)bufinfo.buf, bufinfo.len, x509_csr_ext_cb, &ectx) != 0)
    {
        mbedtls_x509_csr_free(&csr);
        mp_raise_ValueError(MP_ERROR_TEXT("CSR format"));
    }

    if ((csr.private_sig_md != MBEDTLS_MD_SHA1) && (csr.private_sig_md != MBEDTLS_MD_SHA256) && (csr.private_sig_md != MBEDTLS_MD_SHA384) && (csr.private_sig_md != MBEDTLS_MD_SHA512))
    {
        mbedtls_x509_csr_free(&csr);
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("only SHA1, SHA256, SHA384 or SHA512 are supported"));
    }
    if (csr.private_sig_pk != MBEDTLS_PK_ECDSA && csr.private_sig_pk != MBEDTLS_PK_RSA)
    {
        mbedtls_x509_csr_free(&csr);
        mp_raise_ValueError(MP_ERROR_TEXT("only ECDSA and RSA are supported"));
    }

    if (csr.private_ext_types & MBEDTLS_X509_EXT_KEY_USAGE)
    {
        mp_x509_key_usage_t *ku = m_new_obj(mp_x509_key_usage_t);
        ku->base.type = &x509_key_usage_type;
        ku->flags = csr.key_usage;
        mp_obj_list_append(ectx.list, x509_new_extension(x509_new_oid_from_str(mp_obj_new_str("2.5.29.15", 9)), 0, MP_OBJ_FROM_PTR(ku)));
    }
    if (csr.private_ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)
    {
        mp_obj_t gnames = mp_obj_new_list(0, NULL);
        const mbedtls_x509_sequence *cur = &csr.subject_alt_names;
        while (cur != NULL && cur->buf.p != NULL)
        {
            mbedtls_x509_subject_alternative_name san;
            memset(&san, 0, sizeof(san));
            int sret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
            mp_x509_general_name_t *g = m_new_obj(mp_x509_general_name_t);
            if (sret == 0 && (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_RFC822_NAME || san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER))
            {
                g->base.type = &x509_dns_name_type;
                g->kind = 2;
                g->value = mp_obj_new_str((const char *)san.san.unstructured_name.p, san.san.unstructured_name.len);
            }
            else
            {
                g->base.type = &x509_ip_address_type;
                g->kind = 7;
                g->value = mp_obj_new_bytes(cur->buf.p, cur->buf.len);
            }
            if (sret == 0)
            {
                mbedtls_x509_free_subject_alt_name(&san);
            }
            mp_obj_list_append(gnames, MP_OBJ_FROM_PTR(g));
            cur = cur->next;
        }
        mp_x509_san_t *san_o = m_new_obj(mp_x509_san_t);
        san_o->base.type = &x509_san_type;
        san_o->general_names = gnames;
        mp_obj_list_append(ectx.list, x509_new_extension(x509_new_oid_from_str(mp_obj_new_str("2.5.29.17", 9)), 0, MP_OBJ_FROM_PTR(san_o)));
    }

    x509_csr_append_bc_eku(ectx.list, &csr.cri);

    mp_x509_extensions_t *exts = m_new_obj(mp_x509_extensions_t);
    exts->base.type = &x509_extensions_type;
    exts->list = ectx.list;

    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->md_type = csr.private_sig_md;
    switch (HashAlgorithm->md_type)
    {
    case MBEDTLS_MD_SHA1:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha1_type;
        break;
    }
    case MBEDTLS_MD_SHA256:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha256_type;
        break;
    }
    case MBEDTLS_MD_SHA384:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha384_type;
        break;
    }
    case MBEDTLS_MD_SHA512:
    {
        HashAlgorithm->base.type = &hash_algorithm_sha512_type;
        break;
    }
    default:
    {
        break;
    }
    }

    mp_x509_csr_t *CSR = m_new_obj(mp_x509_csr_t);
    CSR->base.type = &x509_csr_type;
    CSR->subject = x509_crt_parse_name(&csr.subject);
    CSR->signature = mp_obj_new_bytes(csr.private_sig.p, csr.private_sig.len);
    CSR->signature_algorithm_oid = x509_new_oid_from_str(x509_crt_parse_oid(&csr.sig_oid, &mp_type_str));
    CSR->signature_hash_algorithm = HashAlgorithm;
    CSR->extensions = MP_OBJ_FROM_PTR(exts);
    CSR->tbs_certrequest_bytes = mp_obj_new_bytes(csr.cri.p, csr.cri.len);
    CSR->public_bytes = mp_obj_new_bytes(csr.raw.p, csr.raw.len);

    {
        const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(csr.private_sig_md);
        unsigned char hash[64];
        int vok = -1;
        if (mdinfo != NULL && mbedtls_md(mdinfo, csr.cri.p, csr.cri.len, hash) == 0)
        {
            vok = mbedtls_pk_verify(&csr.pk, csr.private_sig_md, hash, mbedtls_md_get_size(mdinfo), csr.private_sig.p, csr.private_sig.len);
        }
        CSR->is_signature_valid = mp_obj_new_bool(vok == 0);
    }

    if (mbedtls_pk_get_type(&csr.pk) == MBEDTLS_PK_ECKEY)
    {
        CSR->rsa_public_key = NULL;
        CSR->ec_public_key = ec_parse_keypair(mbedtls_pk_ec(csr.pk), false);
    }
    else if (mbedtls_pk_get_type(&csr.pk) == MBEDTLS_PK_RSA)
    {
        CSR->ec_public_key = NULL;
        CSR->rsa_public_key = rsa_parse_keypair(mbedtls_pk_rsa(csr.pk), false);
    }
    else
    {
        mbedtls_x509_csr_free(&csr);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("only EC or RSA keys are supported"));
    }

    mbedtls_x509_csr_free(&csr);
    return MP_OBJ_FROM_PTR(CSR);
#endif
}
static MP_DEFINE_CONST_FUN_OBJ_1(x509_csr_parse_der_obj, x509_csr_parse_der);

static mp_obj_t x509_csr_parse_pem(mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
    (void)data;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 csr disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CSR)"));
#else
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    size_t inlen = bufinfo.len;
    byte *pembuf = m_new(byte, inlen + 1);
    memcpy(pembuf, bufinfo.buf, inlen);
    pembuf[inlen] = '\0';
    mbedtls_pem_context pem;
    mbedtls_pem_init(&pem);
    size_t use_len = 0;
    int ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----", pembuf, NULL, 0, &use_len);
    m_del(byte, pembuf, inlen + 1);
    if (ret != 0)
    {
        mbedtls_pem_free(&pem);
        mp_raise_ValueError(MP_ERROR_TEXT("CSR format"));
    }
    size_t der_len = 0;
    const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &der_len);
    mp_obj_t der = mp_obj_new_bytes(der_buf, der_len);
    mbedtls_pem_free(&pem);
    return x509_csr_parse_der(der);
#endif
}
static MP_DEFINE_CONST_FUN_OBJ_1(x509_csr_parse_pem_obj, x509_csr_parse_pem);

static mp_obj_t x509_csr_builder_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !(MICROPY_PY_UCRYPTOGRAPHY_X509_CSR && MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE)
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 csr create disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CSR)"));
#else
    (void)args;
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_x509_csr_builder_t *o = m_new_obj(mp_x509_csr_builder_t);
    o->base.type = &x509_csr_builder_type;
    o->subject_name = MP_OBJ_NULL;
    o->extensions = mp_obj_new_list(0, NULL);
    return MP_OBJ_FROM_PTR(o);
#endif
}

static mp_obj_t x509_csr_builder_subject_name(mp_obj_t self_in, mp_obj_t name)
{
    ((mp_x509_csr_builder_t *)MP_OBJ_TO_PTR(self_in))->subject_name = name;
    return self_in;
}
static MP_DEFINE_CONST_FUN_OBJ_2(x509_csr_builder_subject_name_obj, x509_csr_builder_subject_name);

static mp_obj_t x509_csr_builder_add_extension(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args)
{
    mp_x509_csr_builder_t *self = MP_OBJ_TO_PTR(pos_args[0]);
    enum
    {
        ARG_extension,
        ARG_critical
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_extension, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_critical, MP_ARG_OBJ, {.u_obj = mp_const_false}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    mp_obj_t tup[2] = {args[ARG_extension].u_obj, mp_obj_new_bool(mp_obj_is_true(args[ARG_critical].u_obj))};
    mp_obj_list_append(self->extensions, mp_obj_new_tuple(2, tup));
    return pos_args[0];
}
static MP_DEFINE_CONST_FUN_OBJ_KW(x509_csr_builder_add_extension_obj, 2, x509_csr_builder_add_extension);

static mp_obj_t x509_csr_builder_sign(mp_obj_t self_in, mp_obj_t private_key, mp_obj_t algorithm)
{
#if !(MICROPY_PY_UCRYPTOGRAPHY_X509_CSR && MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE)
    (void)self_in;
    (void)private_key;
    (void)algorithm;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("x509 csr create disabled (enable MICROPY_PY_UCRYPTOGRAPHY_X509_CSR)"));
#else
    mp_x509_csr_builder_t *self = MP_OBJ_TO_PTR(self_in);
    if (self->subject_name == MP_OBJ_NULL)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Builder is missing subject_name"));
    }

    mbedtls_md_type_t md = x509_hash_to_md(algorithm);

    mbedtls_x509write_csr req;
    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    int ret = 0;
    mp_obj_t result = mp_const_none;

    mbedtls_x509write_csr_set_md_alg(&req, md);
    crypto_pk_from_private_key(&key, private_key);
    mbedtls_x509write_csr_set_key(&req, &key);

    vstr_t vstr_subject;
    vstr_init(&vstr_subject, 64);
    x509_name_to_string(self->subject_name, &vstr_subject);
    ret = mbedtls_x509write_csr_set_subject_name(&req, vstr_null_terminated_str(&vstr_subject));
    vstr_clear(&vstr_subject);
    if (ret != 0)
    {
        goto cleanup;
    }

    {
        size_t n;
        mp_obj_t *items;
        mp_obj_get_array(self->extensions, &n, &items);
        for (size_t i = 0; i < n; i++)
        {
            mp_obj_t *pair;
            size_t plen;
            mp_obj_get_array(items[i], &plen, &pair);
            ret = x509_apply_extension(&req, true, pair[0], mp_obj_is_true(pair[1]));
            if (ret != 0)
            {
                goto cleanup;
            }
        }
    }

    {
        size_t bufsize = 4096;
        byte *buf = m_new(byte, bufsize);
        int wr = mbedtls_x509write_csr_der(&req, buf, bufsize, mp_random, NULL);
        if (wr < 0)
        {
            m_del(byte, buf, bufsize);
            ret = wr;
            goto cleanup;
        }
        mp_obj_t der = mp_obj_new_bytes(buf + bufsize - wr, wr);
        m_del(byte, buf, bufsize);
        result = x509_csr_parse_der(der);
    }

cleanup:
    mbedtls_pk_free(&key);
    mbedtls_x509write_csr_free(&req);
    if (result == mp_const_none)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("CSR signing failed"));
    }
    return result;
#endif
}
static MP_DEFINE_CONST_FUN_OBJ_3(x509_csr_builder_sign_obj, x509_csr_builder_sign);

static const mp_rom_map_elem_t x509_csr_builder_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_subject_name), MP_ROM_PTR(&x509_csr_builder_subject_name_obj)},
    {MP_ROM_QSTR(MP_QSTR_add_extension), MP_ROM_PTR(&x509_csr_builder_add_extension_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&x509_csr_builder_sign_obj)},
};
static MP_DEFINE_CONST_DICT(x509_csr_builder_locals_dict, x509_csr_builder_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_csr_builder_type,
    MP_QSTR_CertificateSigningRequestBuilder,
    MP_TYPE_FLAG_NONE,
    make_new, x509_csr_builder_make_new,
    locals_dict, &x509_csr_builder_locals_dict);

// PyCA cryptography.x509.oid subpackage.
static const mp_rom_map_elem_t x509_oid_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_oid)},
    {MP_ROM_QSTR(MP_QSTR_ObjectIdentifier), MP_ROM_PTR(&x509_oid_type)},
    {MP_ROM_QSTR(MP_QSTR_NameOID), MP_ROM_PTR(&x509_nameoid_obj)},
    {MP_ROM_QSTR(MP_QSTR_ExtendedKeyUsageOID), MP_ROM_PTR(&x509_ekuoid_obj)},
};
static MP_DEFINE_CONST_DICT(x509_oid_globals, x509_oid_globals_table);
static const mp_obj_module_t x509_oid_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&x509_oid_globals,
};

// cryptography.x509 is a package (module) so `from cryptography.x509.oid import ...` works;
// the flat `from cryptography import x509` keeps working (getattr on the module).
static const mp_rom_map_elem_t x509_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_x509)},
    {MP_ROM_QSTR(MP_QSTR_load_der_x509_certificate), MP_ROM_PTR(&mod_x509_crt_parse_der_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_pem_x509_certificate), MP_ROM_PTR(&x509_crt_parse_pem_obj)},
    {MP_ROM_QSTR(MP_QSTR_Certificate), MP_ROM_PTR(&x509_certificate_type)},
    {MP_ROM_QSTR(MP_QSTR_CertificateBuilder), MP_ROM_PTR(&x509_cert_builder_type)},
    {MP_ROM_QSTR(MP_QSTR_Name), MP_ROM_PTR(&x509_name_type)},
    {MP_ROM_QSTR(MP_QSTR_NameAttribute), MP_ROM_PTR(&x509_name_attribute_type)},
    {MP_ROM_QSTR(MP_QSTR_ObjectIdentifier), MP_ROM_PTR(&x509_oid_type)},
    {MP_ROM_QSTR(MP_QSTR_NameOID), MP_ROM_PTR(&x509_nameoid_obj)},
    {MP_ROM_QSTR(MP_QSTR_SubjectAlternativeName), MP_ROM_PTR(&x509_san_type)},
    {MP_ROM_QSTR(MP_QSTR_DNSName), MP_ROM_PTR(&x509_dns_name_type)},
    {MP_ROM_QSTR(MP_QSTR_IPAddress), MP_ROM_PTR(&x509_ip_address_type)},
    {MP_ROM_QSTR(MP_QSTR_BasicConstraints), MP_ROM_PTR(&x509_basic_constraints_type)},
    {MP_ROM_QSTR(MP_QSTR_KeyUsage), MP_ROM_PTR(&x509_key_usage_type)},
    {MP_ROM_QSTR(MP_QSTR_ExtendedKeyUsage), MP_ROM_PTR(&x509_ext_key_usage_type)},
    {MP_ROM_QSTR(MP_QSTR_ExtendedKeyUsageOID), MP_ROM_PTR(&x509_ekuoid_obj)},
    {MP_ROM_QSTR(MP_QSTR_SubjectKeyIdentifier), MP_ROM_PTR(&x509_ski_type)},
    {MP_ROM_QSTR(MP_QSTR_AuthorityKeyIdentifier), MP_ROM_PTR(&x509_aki_type)},
    {MP_ROM_QSTR(MP_QSTR_UnrecognizedExtension), MP_ROM_PTR(&x509_unrecognized_extension_type)},
    {MP_ROM_QSTR(MP_QSTR_random_serial_number), MP_ROM_PTR(&x509_random_serial_number_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_der_x509_csr), MP_ROM_PTR(&x509_csr_parse_der_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_pem_x509_csr), MP_ROM_PTR(&x509_csr_parse_pem_obj)},
    {MP_ROM_QSTR(MP_QSTR_CertificateSigningRequest), MP_ROM_PTR(&x509_csr_type)},
    {MP_ROM_QSTR(MP_QSTR_CertificateSigningRequestBuilder), MP_ROM_PTR(&x509_csr_builder_type)},
    {MP_ROM_QSTR(MP_QSTR_oid), MP_ROM_PTR(&x509_oid_module)},
};
static MP_DEFINE_CONST_DICT(x509_globals, x509_globals_table);
static const mp_obj_module_t x509_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&x509_globals,
};

static mp_obj_t pk_parse_public_key(mp_obj_t public_key)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(public_key, &bufinfo, MP_BUFFER_READ);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, (const byte *)bufinfo.buf, bufinfo.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("public key"));
    }

    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY)
    {
        mp_obj_t pub_key = ec_parse_keypair(mbedtls_pk_ec(pk), false);
        mbedtls_pk_free(&pk);
        return pub_key;
    }
    else if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA)
    {
        mp_obj_t pub_key = rsa_parse_keypair(mbedtls_pk_rsa(pk), false);
        mbedtls_pk_free(&pk);
        return pub_key;
    }
    else
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("only EC or RSA key are supported"));
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_pk_parse_public_key_obj, pk_parse_public_key);

static mp_obj_t pk_parse_key(mp_obj_t private_key, mp_obj_t password)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(private_key, &bufinfo, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo1;
    bool use_password = mp_get_buffer(password, &bufinfo1, MP_BUFFER_READ);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_key(&pk, (const byte *)bufinfo.buf, bufinfo.len, (use_password ? (const byte *)bufinfo1.buf : NULL), (use_password ? bufinfo1.len : 0), mp_random, NULL) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("private key"));
    }

    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY)
    {
        mp_obj_t priv_key = ec_parse_keypair(mbedtls_pk_ec(pk), true);
        mbedtls_pk_free(&pk);
        return priv_key;
    }
    else if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA)
    {
        mp_obj_t priv_key = rsa_parse_keypair(mbedtls_pk_rsa(pk), true);
        mbedtls_pk_free(&pk);
        return priv_key;
    }
    else
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_InvalidKey, MP_ERROR_TEXT("only EC or RSA keys are supported"));
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_pk_parse_key_obj, pk_parse_key);

// PEM loaders: mbedtls auto-detects PEM once the buffer is NUL-terminated.
static mp_obj_t pk_parse_public_key_pem(mp_obj_t public_key)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(public_key, &bufinfo, MP_BUFFER_READ);
    vstr_t vstr;
    vstr_init(&vstr, bufinfo.len + 1);
    vstr_add_strn(&vstr, bufinfo.buf, bufinfo.len);
    vstr_add_byte(&vstr, 0);
    mp_obj_t nt = mp_obj_new_bytes((const byte *)vstr.buf, vstr.len);
    vstr_clear(&vstr);
    return pk_parse_public_key(nt);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_pk_parse_public_key_pem_obj, pk_parse_public_key_pem);

static mp_obj_t pk_parse_key_pem(mp_obj_t private_key, mp_obj_t password)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(private_key, &bufinfo, MP_BUFFER_READ);
    vstr_t vstr;
    vstr_init(&vstr, bufinfo.len + 1);
    vstr_add_strn(&vstr, bufinfo.buf, bufinfo.len);
    vstr_add_byte(&vstr, 0);
    mp_obj_t nt = mp_obj_new_bytes((const byte *)vstr.buf, vstr.len);
    vstr_clear(&vstr);
    return pk_parse_key(nt, password);
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_pk_parse_key_pem_obj, pk_parse_key_pem);

static const mp_rom_map_elem_t encoding_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_DER), MP_ROM_INT(1)},
    {MP_ROM_QSTR(MP_QSTR_PEM), MP_ROM_INT(2)},
    {MP_ROM_QSTR(MP_QSTR_X962), MP_ROM_INT(3)},
    {MP_ROM_QSTR(MP_QSTR_Raw), MP_ROM_INT(4)},
};

static MP_DEFINE_CONST_DICT(encoding_locals_dict, encoding_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    encoding_type,
    MP_QSTR_Encoding,
    MP_TYPE_FLAG_NONE,
    locals_dict, &encoding_locals_dict);

static const mp_rom_map_elem_t publicformat_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_SubjectPublicKeyInfo), MP_ROM_INT(1)},
    {MP_ROM_QSTR(MP_QSTR_UncompressedPoint), MP_ROM_INT(2)},
    {MP_ROM_QSTR(MP_QSTR_Raw), MP_ROM_INT(3)},
};

static MP_DEFINE_CONST_DICT(publicformat_locals_dict, publicformat_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    publicformat_type,
    MP_QSTR_PublicFormat,
    MP_TYPE_FLAG_NONE,
    locals_dict, &publicformat_locals_dict);

static const mp_rom_map_elem_t privateformat_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_TraditionalOpenSSL), MP_ROM_INT(1)},
    {MP_ROM_QSTR(MP_QSTR_Raw), MP_ROM_INT(2)},
};

static MP_DEFINE_CONST_DICT(privateformat_locals_dict, privateformat_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    privateformat_type,
    MP_QSTR_PrivateFormat,
    MP_TYPE_FLAG_NONE,
    locals_dict, &privateformat_locals_dict);

static mp_obj_t no_encryption(void)
{
    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_0(mod_no_encryption_obj, no_encryption);

static mp_obj_t best_available_encryption_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    (void)type;
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_buffer_info_t b;
    mp_get_buffer_raise(args[0], &b, MP_BUFFER_READ);
    if (b.len == 0)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Password cannot be empty"));
    }
    mp_best_available_encryption_t *o = m_new_obj(mp_best_available_encryption_t);
    o->base.type = &best_available_encryption_type;
    o->password = args[0];
    return MP_OBJ_FROM_PTR(o);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    best_available_encryption_type,
    MP_QSTR_BestAvailableEncryption,
    MP_TYPE_FLAG_NONE,
    make_new, best_available_encryption_make_new);

static mp_obj_t ec_generate_private_key(mp_obj_t curve)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    mp_ec_curve_t *EllipticCurve = MP_OBJ_TO_PTR(curve);
    if (!mp_obj_is_type(EllipticCurve, &ec_curve_secp256r1_type)
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp384r1_type)
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp521r1_type)
#endif
    )
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec curve"));
    }
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init(&ecp);
    mbedtls_ecp_group_load(&ecp.private_grp, EllipticCurve->ecp_group_id);
    if (mbedtls_ecp_gen_keypair(&ecp.private_grp, &ecp.private_d, &ecp.private_Q, mp_random, NULL) != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_ecp_gen_keypair"));
    }

    mp_obj_t priv_key = ec_parse_keypair(&ecp, true);
    mbedtls_ecp_keypair_free(&ecp);
    return priv_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_generate_private_key_obj, ec_generate_private_key);

static mp_obj_t ec_derive_private_key(mp_obj_t private_value, mp_obj_t curve)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    if (!mp_obj_is_int(private_value))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected private_value int"));
    }

    mp_ec_curve_t *EllipticCurve = MP_OBJ_TO_PTR(curve);
    if (!mp_obj_is_type(EllipticCurve, &ec_curve_secp256r1_type)
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp384r1_type)
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        && !mp_obj_is_type(EllipticCurve, &ec_curve_secp521r1_type)
#endif
    )
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of ec curve"));
    }

    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init(&ecp);
    mbedtls_ecp_group_load(&ecp.private_grp, EllipticCurve->ecp_group_id);
    int pksize = mbedtls_mpi_size(&ecp.private_grp.N);
    vstr_t vstr_private_bytes;
    vstr_init_len(&vstr_private_bytes, pksize);
    mp_obj_int_to_bytes(cryptography_small_to_big_int(private_value), pksize, (byte *)vstr_private_bytes.buf, true, false, false);

    if (mbedtls_ecp_read_key(ecp.private_grp.id, &ecp, (const byte *)vstr_private_bytes.buf, vstr_private_bytes.len) != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        vstr_clear(&vstr_private_bytes);
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid private_value for curve"));
    }
    if (mbedtls_ecp_mul(&ecp.private_grp, &ecp.private_Q, &ecp.private_d, &ecp.private_grp.G, mp_random, NULL) != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        vstr_clear(&vstr_private_bytes);
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_ecp_mul"));
    }
    mp_obj_t priv_key = ec_parse_keypair(&ecp, true);
    mbedtls_ecp_keypair_free(&ecp);
    vstr_clear(&vstr_private_bytes);
    return priv_key;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_ec_derive_private_key_obj, ec_derive_private_key);

static const mp_rom_map_elem_t padding_pkcs1v15_locals_dict_table[] = {

};

static MP_DEFINE_CONST_DICT(padding_pkcs1v15_locals_dict, padding_pkcs1v15_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_pkcs1v15_type,
    MP_QSTR_PKCS1V15,
    MP_TYPE_FLAG_NONE,
    locals_dict, &padding_pkcs1v15_locals_dict);

static mp_obj_t padding_calculate_max_pss_salt_length(mp_obj_t key, mp_obj_t hash_algorithm)
{
    if (!mp_obj_is_type(key, &rsa_public_key_type) && !mp_obj_is_type(key, &rsa_private_key_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of rsa.RSAPublicKey or rsa.RSAPrivateKey"));
    }

    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    if (mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm, prehashed not supported"));
    }

    mp_int_t emlen = 0;
    if (mp_obj_is_type(key, &rsa_public_key_type))
    {
        mp_rsa_public_key_t *RSAPublicKey = (mp_rsa_public_key_t *)MP_OBJ_TO_PTR(key);
        emlen = (mp_int_t)(mp_obj_get_int(int_bit_length(RSAPublicKey->public_numbers->n)) + 6) / 8;
    }
    else if (mp_obj_is_type(key, &rsa_private_key_type))
    {
        mp_rsa_private_key_t *RSAPrivateKey = (mp_rsa_private_key_t *)MP_OBJ_TO_PTR(key);
        emlen = (mp_int_t)(mp_obj_get_int(int_bit_length(RSAPrivateKey->public_key->public_numbers->n)) + 6) / 8;
    }

    mp_hash_algorithm_t *HashAlgorithm = MP_OBJ_TO_PTR(hash_algorithm);
    mp_int_t digest_size = mbedtls_md_get_size(mbedtls_md_info_from_type(HashAlgorithm->md_type));
    mp_int_t salt_length = emlen - digest_size - 2;
    return mp_obj_new_int(salt_length);
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_padding_calculate_max_pss_salt_length_obj, padding_calculate_max_pss_salt_length);

static mp_obj_t padding_pss_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_PSS
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)all_args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("PSS disabled (enable MICROPY_PY_UCRYPTOGRAPHY_PSS)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 2, true);
    enum
    {
        ARG_mgf,
        ARG_salt_length
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_mgf, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_salt_length, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t mgf = args[ARG_mgf].u_obj;
    mp_obj_t salt_length = args[ARG_salt_length].u_obj;

    if (!mp_obj_is_int(salt_length))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected salt_length int"));
    }

    if (!mp_obj_is_type(mgf, &padding_mgf1_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.MGF1"));
    }

    mp_padding_pss_t *PADDING_PSS = m_new_obj(mp_padding_pss_t);
    PADDING_PSS->base.type = &padding_pss_type;
    PADDING_PSS->name = mp_obj_new_str("EMSA-PSS", strlen("EMSA-PSS"));
    PADDING_PSS->mgf = mgf;
    PADDING_PSS->salt_length = mp_obj_get_int(salt_length);

    return MP_OBJ_FROM_PTR(PADDING_PSS);
#endif
}

static void padding_pss_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_padding_pss_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;

    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_MAX_LENGTH)
            {
                dest[0] = mp_obj_new_int(0);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t padding_pss_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_MAX_LENGTH), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(padding_pss_locals_dict, padding_pss_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_pss_type,
    MP_QSTR_PSS,
    MP_TYPE_FLAG_NONE,
    make_new, padding_pss_make_new,
    attr, padding_pss_attr,
    locals_dict, &padding_pss_locals_dict);

static mp_obj_t padding_oaep_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_OAEP
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)all_args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("OAEP disabled (enable MICROPY_PY_UCRYPTOGRAPHY_OAEP)"));
#else
    mp_arg_check_num(n_args, n_kw, 0, 3, true);
    enum
    {
        ARG_mgf,
        ARG_algorithm,
        ARG_label
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_mgf, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_algorithm, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_label, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t mgf = args[ARG_mgf].u_obj;
    mp_obj_t algorithm = args[ARG_algorithm].u_obj;
    mp_obj_t label = args[ARG_label].u_obj;

    if (!mp_obj_is_type(mgf, &padding_mgf1_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.MGF1"));
    }

    if (!mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    mp_padding_oaep_t *PADDING_OAEP = m_new_obj(mp_padding_oaep_t);
    PADDING_OAEP->base.type = &padding_oaep_type;
    PADDING_OAEP->name = mp_obj_new_str("EME-OAEP", strlen("EME-OAEP"));
    PADDING_OAEP->mgf = mgf;
    PADDING_OAEP->label = label;

    if (mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm, prehashed not supported"));
    }
    else
    {
        mp_hash_algorithm_t *HashAlgorithm = MP_OBJ_TO_PTR(algorithm);
        PADDING_OAEP->algorithm = HashAlgorithm;
    }

    return MP_OBJ_FROM_PTR(PADDING_OAEP);
#endif
}

static const mp_rom_map_elem_t padding_oaep_locals_dict_table[] = {

};

static MP_DEFINE_CONST_DICT(padding_oaep_locals_dict, padding_oaep_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_oaep_type,
    MP_QSTR_OAEP,
    MP_TYPE_FLAG_NONE,
    make_new, padding_oaep_make_new,
    locals_dict, &padding_oaep_locals_dict);

#if MICROPY_PY_UCRYPTOGRAPHY_MGF1
static const mp_rom_map_elem_t padding_mgf1_locals_dict_table[] = {

};

static MP_DEFINE_CONST_DICT(padding_mgf1_locals_dict, padding_mgf1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_mgf1_type,
    MP_QSTR_MGF1,
    MP_TYPE_FLAG_NONE,
    locals_dict, &padding_mgf1_locals_dict);
#endif

static mp_obj_t padding_pkcs1v15(void)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_PKCS1V15
    mp_raise_NotImplementedError(MP_ERROR_TEXT("PKCS1v15 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_PKCS1V15)"));
#else
    mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = m_new_obj(mp_padding_pkcs1v15_t);
    PADDING_PKCS1V15->base.type = &padding_pkcs1v15_type;
    PADDING_PKCS1V15->name = mp_obj_new_str("EMSA-PKCS1-v1_5", strlen("EMSA-PKCS1-v1_5"));

    return MP_OBJ_FROM_PTR(PADDING_PKCS1V15);
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_0(mod_padding_pkcs1v15_obj, padding_pkcs1v15);

static mp_obj_t padding_mgf1(mp_obj_t algorithm)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_MGF1
    (void)algorithm;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("MGF1 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_MGF1)"));
#else
    if (!mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    mp_padding_mgf1_t *PADDING_MGF1 = m_new_obj(mp_padding_mgf1_t);
    PADDING_MGF1->base.type = &padding_mgf1_type;

    if (mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm, prehashed not supported"));
    }
    else
    {
        mp_hash_algorithm_t *HashAlgorithm = MP_OBJ_TO_PTR(algorithm);
        PADDING_MGF1->algorithm = HashAlgorithm;
    }

    return MP_OBJ_FROM_PTR(PADDING_MGF1);
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_padding_mgf1_obj, padding_mgf1);

static mp_obj_t rsa_verify(size_t n_args, const mp_obj_t *args)
{
    mp_obj_t signature = args[1];
    mp_buffer_info_t bufinfo_signature;
    mp_get_buffer_raise(signature, &bufinfo_signature, MP_BUFFER_READ);

    mp_obj_t data = args[2];
    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    mp_obj_t padding = args[3];
    if (!(mp_obj_get_type(padding) == &mp_type_NoneType) && !mp_obj_is_type(padding, &padding_pss_type) && !mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PSS or padding.PKCS1v15 or None"));
    }

    mp_obj_t algorithm = args[4];
    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType) && mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PKCS1v15 for hashes algorithm None"));
    }

    vstr_t vstr_digest;
    mp_hash_algorithm_t *HashAlgorithm = cryptography_hash_digest(algorithm, &bufinfo_data, &vstr_digest);

    mp_rsa_public_key_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_rsa_public_numbers_t *RSAPublicNumbers = self->public_numbers;

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, RSAPublicNumbers->n, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, RSAPublicNumbers->e, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    int ret = 1;
    if ((ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E)) != 0)
    {
        mbedtls_pk_free(&pk);
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_import"));
    }

    mp_int_t salt_length = vstr_digest.len;
    if (mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_padding_pss_t *PADDING_PSS = MP_OBJ_TO_PTR(padding);
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_PSS->mgf->algorithm->md_type);
    }
    else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    }

    if (mp_obj_is_type(padding, &padding_pkcs1v15_type) || mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_int_t md_type = (HashAlgorithm != NULL ? HashAlgorithm->md_type : MBEDTLS_MD_NONE);
        ret = mbedtls_pk_verify(&pk, md_type, (const byte *)vstr_digest.buf, salt_length, (const byte *)bufinfo_signature.buf, bufinfo_signature.len);
    }
    else
    {
        byte buf[MBEDTLS_MPI_MAX_SIZE];
        memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
        ret = rsa_pka_modexp(rsa, 0, (const byte *)bufinfo_signature.buf, buf);
        if (ret == 0)
        {
            ret = memcmp(buf, (const byte *)vstr_digest.buf, vstr_digest.len);
        }
    }

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    vstr_clear(&vstr_digest);

    if (ret != 0)
    {
        mp_raise_msg_varg(&mp_type_InvalidSignature, MP_ERROR_TEXT("%d"), ret);
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_rsa_verify_obj, 5, 5, rsa_verify);

static mp_obj_t rsa_encrypt(size_t n_args, const mp_obj_t *args)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    mp_obj_t plaintext = args[1];
    mp_buffer_info_t bufinfo_plaintext;
    mp_get_buffer_raise(plaintext, &bufinfo_plaintext, MP_BUFFER_READ);

    mp_obj_t padding = args[2];
    if (!mp_obj_is_type(padding, &padding_oaep_type) && !mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.OAEP or padding.PKCS1v15"));
    }

    mp_rsa_public_key_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_rsa_public_numbers_t *RSAPublicNumbers = self->public_numbers;

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, RSAPublicNumbers->n, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, RSAPublicNumbers->e, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mp_obj_t enc = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E)) == 0)
    {
        if (mp_obj_is_type(padding, &padding_oaep_type))
        {
            mp_padding_oaep_t *PADDING_OAEP = MP_OBJ_TO_PTR(padding);
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_OAEP->mgf->algorithm->md_type);
        }
        else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
        {
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
        }

        byte buf[MBEDTLS_MPI_MAX_SIZE];
        memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
        size_t olen = 0;
        ret = mbedtls_pk_encrypt(&pk, (const byte *)bufinfo_plaintext.buf, bufinfo_plaintext.len, buf, &olen, sizeof(buf), mp_random, NULL);
        if (ret == 0)
        {
            enc = mp_obj_new_bytes((const byte *)buf, olen);
        }
    }

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);

    if (ret != 0)
    {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("rsa_encrypt"));
    }

    return enc;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_rsa_encrypt_obj, 3, 3, rsa_encrypt);

static mp_obj_t rsa_public_numbers(mp_obj_t obj)
{
    mp_rsa_public_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_numbers;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_rsa_public_numbers_obj, rsa_public_numbers);

static mp_obj_t rsa_public_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_rsa_public_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;

    (void)format;

    if (mp_obj_get_int(encoding) == SERIALIZATION_ENCODING_PEM)
    {
        return rsa_key_dumps(self->public_numbers, MP_OBJ_NULL, encoding);
    }
    return self->public_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_rsa_public_bytes_obj, 1, rsa_public_bytes);

static void rsa_public_key_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_rsa_public_key_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;

    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_key_size)
            {
                dest[0] = int_bit_length(self->public_numbers->n);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t rsa_public_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(&mod_rsa_public_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_rsa_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_OBJ_FROM_PTR(&mod_rsa_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_encrypt), MP_OBJ_FROM_PTR(&mod_rsa_encrypt_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(rsa_public_key_locals_dict, rsa_public_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    rsa_public_key_type,
    MP_QSTR_RSAPublicKey,
    MP_TYPE_FLAG_NONE,
    attr, rsa_public_key_attr,
    locals_dict, &rsa_public_key_locals_dict);

static mp_obj_t rsa_public_numbers_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 2, 2, true);
    mp_obj_t e = args[0];
    mp_obj_t n = args[1];
    if (!mp_obj_is_int(e))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected E int"));
    }
    if (!mp_obj_is_int(n))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected N int"));
    }

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, n, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, e, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mp_obj_t public_numbers = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E)) == 0)
    {
        mp_obj_t pub_key = rsa_parse_keypair(rsa, false);
        mp_rsa_public_key_t *RSAPublicKey = MP_OBJ_TO_PTR(pub_key);
        public_numbers = RSAPublicKey->public_numbers;
    }

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);

    if (ret != 0)
    {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("rsa_public_numbers"));
    }

    return public_numbers;
}

static mp_obj_t rsa_public_numbers_public_key(mp_obj_t obj)
{
    mp_rsa_public_numbers_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_rsa_public_numbers_public_key_obj, rsa_public_numbers_public_key);

static void rsa_public_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_rsa_public_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_e)
            {
                dest[0] = self->e;
                return;
            }
            if (attr == MP_QSTR_n)
            {
                dest[0] = self->n;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t rsa_public_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_n), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_e), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_rsa_public_numbers_public_key_obj)},
};

static MP_DEFINE_CONST_DICT(rsa_public_numbers_locals_dict, rsa_public_numbers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    rsa_public_numbers_type,
    MP_QSTR_RSAPublicNumbers,
    MP_TYPE_FLAG_NONE,
    make_new, rsa_public_numbers_make_new,
    attr, rsa_public_numbers_attr,
    locals_dict, &rsa_public_numbers_locals_dict);

static mp_obj_t rsa_private_numbers(mp_obj_t obj)
{
    mp_rsa_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_numbers;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_rsa_private_numbers_obj, rsa_private_numbers);

static mp_obj_t rsa_decrypt(size_t n_args, const mp_obj_t *args)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    mp_obj_t ciphertext = args[1];
    mp_buffer_info_t bufinfo_ciphertext;
    mp_get_buffer_raise(ciphertext, &bufinfo_ciphertext, MP_BUFFER_READ);

    mp_obj_t padding = args[2];
    if (!mp_obj_is_type(padding, &padding_oaep_type) && !mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.OAEP or padding.PKCS1v15"));
    }

    mp_rsa_private_key_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_rsa_private_numbers_t *RSAPrivateNumbers = self->private_numbers;

    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, RSAPrivateNumbers->p, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, RSAPrivateNumbers->q, true);

    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, RSAPrivateNumbers->d, true);

    // dmp1/dmq1/iqmp (CRT params) are recomputed by mbedtls_rsa_complete().
    mp_rsa_public_numbers_t *RSAPublicNumbers = self->public_key->public_numbers;

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, RSAPublicNumbers->e, true);

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, RSAPublicNumbers->n, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mp_obj_t decrypt = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E)) == 0)
    {
        if ((ret = mbedtls_rsa_complete(rsa)) == 0)
        {
            if (mp_obj_is_type(padding, &padding_oaep_type))
            {
                mp_padding_oaep_t *PADDING_OAEP = MP_OBJ_TO_PTR(padding);
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_OAEP->mgf->algorithm->md_type);
            }
            else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
            {
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
            }

            byte buf[MBEDTLS_MPI_MAX_SIZE];
            memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
            size_t olen = 0;
            if ((ret = mbedtls_pk_decrypt(&pk, (const byte *)bufinfo_ciphertext.buf, bufinfo_ciphertext.len, buf, &olen, sizeof(buf), mp_random, NULL)) == 0)
            {
                decrypt = mp_obj_new_bytes((const byte *)buf, olen);
            }
        }
    }

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);

    if (ret != 0)
    {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("rsa_decrypt"));
    }

    return decrypt;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_rsa_decrypt_obj, 3, 3, rsa_decrypt);

static mp_obj_t rsa_sign(size_t n_args, const mp_obj_t *args)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif

    mp_obj_t data = args[1];
    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    mp_obj_t padding = args[2];
    if (!(mp_obj_get_type(padding) == &mp_type_NoneType) && !mp_obj_is_type(padding, &padding_pss_type) && !mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PSS or padding.PKCS1v15 or None"));
    }

    mp_obj_t algorithm = args[3];
    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType) && mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PKCS1v15 for hashes algorithm None"));
    }

    vstr_t vstr_digest;
    mp_hash_algorithm_t *HashAlgorithm = cryptography_hash_digest(algorithm, &bufinfo_data, &vstr_digest);

    mp_rsa_private_key_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_rsa_private_numbers_t *RSAPrivateNumbers = self->private_numbers;

    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, RSAPrivateNumbers->p, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, RSAPrivateNumbers->q, true);

    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, RSAPrivateNumbers->d, true);

    // dmp1/dmq1/iqmp (CRT params) are recomputed by mbedtls_rsa_complete().
    mp_rsa_public_numbers_t *RSAPublicNumbers = self->public_key->public_numbers;

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, RSAPublicNumbers->e, true);

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, RSAPublicNumbers->n, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mp_obj_t sign = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E)) == 0)
    {
        if ((ret = mbedtls_rsa_complete(rsa)) == 0)
        {

            mp_int_t salt_length = vstr_digest.len;
            if (mp_obj_is_type(padding, &padding_pss_type))
            {
                mp_padding_pss_t *PADDING_PSS = MP_OBJ_TO_PTR(padding);
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_PSS->mgf->algorithm->md_type);
            }
            else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
            {
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
            }

            byte buf[MBEDTLS_MPI_MAX_SIZE];
            memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
            size_t olen = 0;

            if (mp_obj_is_type(padding, &padding_pkcs1v15_type) || mp_obj_is_type(padding, &padding_pss_type))
            {
                mp_int_t md_type = (HashAlgorithm != NULL ? HashAlgorithm->md_type : MBEDTLS_MD_NONE);
                ret = mbedtls_pk_sign(&pk, md_type, (const byte *)vstr_digest.buf, salt_length, buf, MBEDTLS_MPI_MAX_SIZE, &olen, mp_random, NULL);
            }
            else
            {
                if ((ret = rsa_pka_modexp(rsa, 1, (const byte *)vstr_digest.buf, buf)) == 0)
                {
                    olen = mbedtls_mpi_size(&N);
                }
            }

            if (ret == 0)
            {
                sign = mp_obj_new_bytes((const byte *)buf, olen);
            }
        }
    }

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    vstr_clear(&vstr_digest);

    if (ret != 0)
    {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("rsa_sign"));
    }

    return sign;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_rsa_sign_obj, 4, 4, rsa_sign);

static mp_obj_t rsa_private_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
        ARG_encryption_algorithm,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encryption_algorithm, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_rsa_private_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;
    mp_obj_t encryption_algorithm = vals[ARG_encryption_algorithm].u_obj;

    (void)format;

    if (mp_obj_is_type(encryption_algorithm, &best_available_encryption_type))
    {
        if (!mp_obj_is_int(encoding) || mp_obj_get_int(encoding) != SERIALIZATION_ENCODING_PEM)
        {
            mp_raise_ValueError(MP_ERROR_TEXT("Encrypted private keys require PEM encoding"));
        }
        return serialization_encrypt_trad_pem(self->private_bytes, "RSA PRIVATE KEY", ((mp_best_available_encryption_t *)MP_OBJ_TO_PTR(encryption_algorithm))->password);
    }

    if (mp_obj_get_int(encoding) == SERIALIZATION_ENCODING_PEM)
    {
        return rsa_key_dumps(self->public_key->public_numbers, self->private_numbers, encoding);
    }
    return self->private_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_rsa_private_bytes_obj, 1, rsa_private_bytes);

static mp_obj_t rsa_public_key(mp_obj_t obj)
{
    mp_rsa_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_rsa_public_key_obj, rsa_public_key);

static void rsa_private_key_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_rsa_private_key_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_key_size)
            {
                dest[0] = int_bit_length(self->public_key->public_numbers->n);
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t rsa_private_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_private_numbers), MP_ROM_PTR(&mod_rsa_private_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_decrypt), MP_ROM_PTR(&mod_rsa_decrypt_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mod_rsa_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_private_bytes), MP_ROM_PTR(&mod_rsa_private_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_rsa_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(0)},
};

static MP_DEFINE_CONST_DICT(rsa_private_key_locals_dict, rsa_private_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    rsa_private_key_type,
    MP_QSTR_RSAPrivateKey,
    MP_TYPE_FLAG_NONE,
    attr, rsa_private_key_attr,
    locals_dict, &rsa_private_key_locals_dict);

static mp_obj_t rsa_private_numbers_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
    mp_arg_check_num(n_args, n_kw, 7, 7, true);
    enum
    {
        ARG_p,
        ARG_q,
        ARG_d,
        ARG_dmp1,
        ARG_dmq1,
        ARG_iqmp,
        ARG_public_numbers
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_p, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_q, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_d, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_dmp1, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_dmq1, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_iqmp, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_public_numbers, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t p = args[ARG_p].u_obj;
    mp_obj_t q = args[ARG_q].u_obj;
    mp_obj_t d = args[ARG_d].u_obj;
    mp_obj_t dmp1 = args[ARG_dmp1].u_obj;
    mp_obj_t dmq1 = args[ARG_dmq1].u_obj;
    mp_obj_t iqmp = args[ARG_iqmp].u_obj;
    mp_obj_t public_numbers = args[ARG_public_numbers].u_obj;

    if (!mp_obj_is_int(p))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected P int"));
    }
    if (!mp_obj_is_int(q))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Q int"));
    }
    if (!mp_obj_is_int(d))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected D int"));
    }
    if (!mp_obj_is_int(dmp1))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected DMP1 int"));
    }
    if (!mp_obj_is_int(dmq1))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected DMQ1 int"));
    }
    if (!mp_obj_is_int(iqmp))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected IQMP int"));
    }
    mp_rsa_public_numbers_t *RSAPublicNumbers = MP_OBJ_TO_PTR(public_numbers);
    if (!mp_obj_is_type(RSAPublicNumbers, &rsa_public_numbers_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of rsa.RSAPublicNumbers"));
    }

    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, p, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, q, true);

    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, d, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, RSAPublicNumbers->e, true);

    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, RSAPublicNumbers->n, true);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    mp_obj_t private_numbers = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E)) == 0)
    {
        if ((ret = mbedtls_rsa_complete(rsa)) == 0)
        {
            mp_obj_t priv_key = rsa_parse_keypair(rsa, true);
            mp_rsa_private_key_t *RSAPrivateKey = MP_OBJ_TO_PTR(priv_key);
            private_numbers = RSAPrivateKey->private_numbers;
        }
    }

    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&N);
    mbedtls_pk_free(&pk);

    if (ret != 0)
    {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("rsa_private_numbers"));
    }

    return private_numbers;
}

static mp_obj_t rsa_private_numbers_private_key(mp_obj_t obj)
{
    mp_rsa_private_numbers_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_rsa_private_numbers_private_key_obj, rsa_private_numbers_private_key);

static void rsa_private_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_rsa_private_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_p)
            {
                dest[0] = self->p;
                return;
            }
            if (attr == MP_QSTR_q)
            {
                dest[0] = self->q;
                return;
            }
            if (attr == MP_QSTR_d)
            {
                dest[0] = self->d;
                return;
            }
            if (attr == MP_QSTR_dmp1)
            {
                dest[0] = self->dmp1;
                return;
            }
            if (attr == MP_QSTR_dmq1)
            {
                dest[0] = self->dmq1;
                return;
            }
            if (attr == MP_QSTR_iqmp)
            {
                dest[0] = self->iqmp;
                return;
            }
            if (attr == MP_QSTR_public_numbers)
            {
                dest[0] = self->public_numbers;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t rsa_private_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_p), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_q), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_d), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_dmp1), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_dmq1), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_iqmp), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_private_key), MP_ROM_PTR(&mod_rsa_private_numbers_private_key_obj)},
};

static MP_DEFINE_CONST_DICT(rsa_private_numbers_locals_dict, rsa_private_numbers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    rsa_private_numbers_type,
    MP_QSTR_RSAPrivateNumbers,
    MP_TYPE_FLAG_NONE,
    make_new, rsa_private_numbers_make_new,
    attr, rsa_private_numbers_attr,
    locals_dict, &rsa_private_numbers_locals_dict);

static mp_obj_t rsa_crt_iqmp(mp_obj_t p, mp_obj_t q)
{
    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, p, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, q, true);

    mbedtls_mpi QP;
    mbedtls_mpi_init(&QP);

    mbedtls_mpi_inv_mod(&QP, &Q, &P);

    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);

    if (mbedtls_mpi_cmp_int(&QP, 0) != 0)
    {
        mp_obj_t pq = mbedtls_mpi_write_binary_to_mp_obj(&QP, true);
        mbedtls_mpi_free(&QP);
        return pq;
    }

    mbedtls_mpi_free(&QP);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_rsa_crt_iqmp_obj, rsa_crt_iqmp);

static mp_obj_t rsa_crt_dmp1(mp_obj_t d, mp_obj_t p)
{
    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, d, true);

    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, p, true);

    mbedtls_mpi Psub1;
    mbedtls_mpi_init(&Psub1);
    mbedtls_mpi_sub_int(&Psub1, &P, 1);

    mbedtls_mpi DP;
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_mod_mpi(&DP, &D, &Psub1);

    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Psub1);

    if (mbedtls_mpi_cmp_int(&DP, 0) != 0)
    {
        mp_obj_t dmp1 = mbedtls_mpi_write_binary_to_mp_obj(&DP, true);
        mbedtls_mpi_free(&DP);
        return dmp1;
    }

    mbedtls_mpi_free(&DP);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_rsa_crt_dmp1_obj, rsa_crt_dmp1);

static mp_obj_t rsa_crt_dmq1(mp_obj_t d, mp_obj_t q)
{
    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, d, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, q, true);

    mbedtls_mpi Qsub1;
    mbedtls_mpi_init(&Qsub1);
    mbedtls_mpi_sub_int(&Qsub1, &Q, 1);

    mbedtls_mpi DQ;
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_mod_mpi(&DQ, &D, &Qsub1);

    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&Qsub1);

    if (mbedtls_mpi_cmp_int(&DQ, 0) != 0)
    {
        mp_obj_t dmq1 = mbedtls_mpi_write_binary_to_mp_obj(&DQ, true);
        mbedtls_mpi_free(&DQ);
        return dmq1;
    }

    mbedtls_mpi_free(&DQ);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_rsa_crt_dmq1_obj, rsa_crt_dmq1);

static mp_obj_t rsa_recover_prime_factors(mp_obj_t n, mp_obj_t e, mp_obj_t d)
{
    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_read_binary_from_mp_obj(&N, n, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, e, true);

    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_read_binary_from_mp_obj(&D, d, true);

    mbedtls_mpi P;
    mbedtls_mpi_init(&P);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);

    mp_obj_t recover_prime_factor = mp_const_none;
    int ret = -1;
    if ((ret = mbedtls_rsa_deduce_primes(&N, &D, &E, &P, &Q)) == 0)
    {
        mp_obj_t pq[2] = {mbedtls_mpi_write_binary_to_mp_obj(&P, true), mbedtls_mpi_write_binary_to_mp_obj(&Q, true)};
        recover_prime_factor = mp_obj_new_tuple(2, pq);
    }

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);

    return recover_prime_factor;
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_rsa_recover_prime_factors_obj, rsa_recover_prime_factors);

static mp_obj_t rsa_generate_private_key(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    enum
    {
        ARG_public_exponent,
        ARG_key_size
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_public_exponent, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_INT, {.u_int = 65537}},
        {MP_QSTR_key_size, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_INT, {.u_int = 2048}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    int ret = 1;
    if ((ret = mbedtls_rsa_gen_key(rsa, mp_random, NULL, vals[ARG_key_size].u_int, vals[ARG_public_exponent].u_int)) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_gen_key"));
    }

    mp_obj_t priv_key = rsa_parse_keypair(rsa, true);
    mbedtls_pk_free(&pk);
    return priv_key;
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_rsa_generate_private_key_obj, 0, rsa_generate_private_key);

static mp_obj_t ed25519_private_key_from_private_bytes(mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_ED25519
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ed25519 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_ED25519)"));
#else
    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (bufinfo_data.len < EDSIGN_SECRET_KEY_SIZE)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("private_bytes must be 32 bytes len"));
    }

    vstr_t vstr_pkey;
    vstr_init_len(&vstr_pkey, EDSIGN_PUBLIC_KEY_SIZE);

    edsign_sec_to_pub((byte *)vstr_pkey.buf, (byte *)bufinfo_data.buf);

    mp_ed25519_public_key_t *ED25519_PUBLIC_KEY = m_new_obj(mp_ed25519_public_key_t);
    ED25519_PUBLIC_KEY->base.type = &ed25519_public_key_type;
    ED25519_PUBLIC_KEY->public_bytes = mp_obj_new_bytes((const byte *)vstr_pkey.buf, vstr_pkey.len);

    mp_ed25519_private_key_t *ED25519_PRIVATE_KEY = m_new_obj(mp_ed25519_private_key_t);
    ED25519_PRIVATE_KEY->base.type = &ed25519_private_key_type;
    ED25519_PRIVATE_KEY->public_key = ED25519_PUBLIC_KEY;
    ED25519_PRIVATE_KEY->private_bytes = mp_obj_new_bytes((const byte *)bufinfo_data.buf, bufinfo_data.len);

    vstr_clear(&vstr_pkey);

    return MP_OBJ_FROM_PTR(ED25519_PRIVATE_KEY);
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ed25519_private_key_from_private_bytes_obj, ed25519_private_key_from_private_bytes);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ed25519_private_key_from_private_bytes_obj, MP_ROM_PTR(&mod_ed25519_private_key_from_private_bytes_obj));

static mp_obj_t ed25519_private_key_generate(void)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_ED25519
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ed25519 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_ED25519)"));
#else
    vstr_t vstr_skey;
    vstr_init_len(&vstr_skey, EDSIGN_SECRET_KEY_SIZE);
    mp_random(NULL, (byte *)vstr_skey.buf, vstr_skey.len);
    mp_obj_t skey_o = mp_obj_new_bytes((const byte *)vstr_skey.buf, vstr_skey.len);

    mp_ed25519_private_key_t *ED25519_PRIVATE_KEY = ed25519_private_key_from_private_bytes(skey_o);

    vstr_clear(&vstr_skey);

    return MP_OBJ_FROM_PTR(ED25519_PRIVATE_KEY);
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_0(mod_ed25519_private_key_generate_obj, ed25519_private_key_generate);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ed25519_private_key_generate_obj, MP_ROM_PTR(&mod_ed25519_private_key_generate_obj));

static mp_obj_t ed25519_private_key_public_key(mp_obj_t obj)
{
    mp_ed25519_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ed25519_private_key_public_key_obj, ed25519_private_key_public_key);

static mp_obj_t ed25519_private_key_private_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
        ARG_encryption_algorithm,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encryption_algorithm, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_ed25519_private_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;
    mp_obj_t encryption_algorithm = vals[ARG_encryption_algorithm].u_obj;

    (void)encoding;
    (void)format;
    (void)encryption_algorithm;

    return self->private_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_ed25519_private_key_private_bytes_obj, 1, ed25519_private_key_private_bytes);

static mp_obj_t ed25519_private_key_sign(mp_obj_t obj, mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_ED25519
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ed25519 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_ED25519)"));
#else
    mp_ed25519_private_key_t *self = MP_OBJ_TO_PTR(obj);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_private_bytes;
    mp_get_buffer_raise(self->private_bytes, &bufinfo_private_bytes, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(self->public_key->public_bytes, &bufinfo_public_bytes, MP_BUFFER_READ);

    vstr_t vstr_signature;
    vstr_init_len(&vstr_signature, EDSIGN_SIGNATURE_SIZE);
    edsign_sign((byte *)vstr_signature.buf, (const byte *)bufinfo_public_bytes.buf, (const byte *)bufinfo_private_bytes.buf, (const byte *)bufinfo_data.buf, bufinfo_data.len);

    mp_obj_t signature_o = mp_obj_new_bytes((const byte *)vstr_signature.buf, vstr_signature.len);

    vstr_clear(&vstr_signature);

    return signature_o;
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_ed25519_private_key_sign_obj, ed25519_private_key_sign);

static const mp_rom_map_elem_t ed25519_private_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_generate), MP_ROM_PTR(&mod_static_ed25519_private_key_generate_obj)},
    {MP_ROM_QSTR(MP_QSTR_from_private_bytes), MP_ROM_PTR(&mod_static_ed25519_private_key_from_private_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_ed25519_private_key_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_private_bytes), MP_ROM_PTR(&mod_ed25519_private_key_private_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mod_ed25519_private_key_sign_obj)},
};

static MP_DEFINE_CONST_DICT(ed25519_private_key_locals_dict, ed25519_private_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ed25519_private_key_type,
    MP_QSTR_Ed25519PrivateKey,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ed25519_private_key_locals_dict);

static mp_obj_t ed25519_public_key_from_public_bytes(mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_ED25519
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ed25519 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_ED25519)"));
#else
    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (bufinfo_data.len < EDSIGN_PUBLIC_KEY_SIZE)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("public_bytes must be 32 bytes len"));
    }

    mp_ed25519_public_key_t *ED25519_PUBLIC_KEY = m_new_obj(mp_ed25519_public_key_t);
    ED25519_PUBLIC_KEY->base.type = &ed25519_public_key_type;
    ED25519_PUBLIC_KEY->public_bytes = mp_obj_new_bytes((const byte *)bufinfo_data.buf, bufinfo_data.len);

    return MP_OBJ_FROM_PTR(ED25519_PUBLIC_KEY);
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ed25519_public_key_from_public_bytes_obj, ed25519_public_key_from_public_bytes);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ed25519_public_key_from_public_bytes_obj, MP_ROM_PTR(&mod_ed25519_public_key_from_public_bytes_obj));

static mp_obj_t ed25519_public_key_public_bytes(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_self,
        ARG_encoding,
        ARG_format,
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_encoding, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_format, MP_ARG_REQUIRED | MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_ed25519_public_key_t *self = vals[ARG_self].u_obj;
    mp_obj_t encoding = vals[ARG_encoding].u_obj;
    mp_obj_t format = vals[ARG_format].u_obj;

    (void)encoding;
    (void)format;

    return self->public_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_ed25519_public_key_public_bytes_obj, 1, ed25519_public_key_public_bytes);

static mp_obj_t ed25519_public_key_verify(mp_obj_t obj, mp_obj_t signature, mp_obj_t data)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_ED25519
    mp_raise_NotImplementedError(MP_ERROR_TEXT("ed25519 disabled (enable MICROPY_PY_UCRYPTOGRAPHY_ED25519)"));
#else
    mp_ed25519_public_key_t *self = MP_OBJ_TO_PTR(obj);

    mp_buffer_info_t bufinfo_signature;
    mp_get_buffer_raise(signature, &bufinfo_signature, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_public_bytes;
    mp_get_buffer_raise(self->public_bytes, &bufinfo_public_bytes, MP_BUFFER_READ);

    mp_int_t ret = edsign_verify((const byte *)bufinfo_signature.buf, (const byte *)bufinfo_public_bytes.buf, (const byte *)bufinfo_data.buf, bufinfo_data.len);
    if (!ret)
    {
        mp_raise_msg_varg(&mp_type_InvalidSignature, MP_ERROR_TEXT("%d"), ret);
    }

    return mp_const_none;
#endif
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_ed25519_public_key_verify_obj, ed25519_public_key_verify);

static const mp_rom_map_elem_t ed25519_public_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_from_public_bytes), MP_ROM_PTR(&mod_static_ed25519_public_key_from_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_ed25519_public_key_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&mod_ed25519_public_key_verify_obj)},
};

static MP_DEFINE_CONST_DICT(ed25519_public_key_locals_dict, ed25519_public_key_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ed25519_public_key_type,
    MP_QSTR_Ed25519PublicKey,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ed25519_public_key_locals_dict);

static const mp_rom_map_elem_t exceptions_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_InvalidSignature), MP_ROM_PTR(&mp_type_InvalidSignature)},
    {MP_ROM_QSTR(MP_QSTR_AlreadyFinalized), MP_ROM_PTR(&mp_type_AlreadyFinalized)},
    {MP_ROM_QSTR(MP_QSTR_UnsupportedAlgorithm), MP_ROM_PTR(&mp_type_UnsupportedAlgorithm)},
    {MP_ROM_QSTR(MP_QSTR_InvalidKey), MP_ROM_PTR(&mp_type_InvalidKey)},
    {MP_ROM_QSTR(MP_QSTR_InvalidToken), MP_ROM_PTR(&mp_type_InvalidToken)},
    {MP_ROM_QSTR(MP_QSTR_InvalidTag), MP_ROM_PTR(&mp_type_InvalidTag)},
};

static MP_DEFINE_CONST_DICT(exceptions_locals_dict, exceptions_locals_dict_table);

static const mp_obj_module_t exceptions_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&exceptions_locals_dict,
};

static mp_obj_t aesgcm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_AESGCM
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("AESGCM disabled (enable MICROPY_PY_UCRYPTOGRAPHY_AESGCM)"));
#else
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_obj_t key = args[0];

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(key, &bufinfo_key, MP_BUFFER_READ);

    mp_ciphers_aesgcm_t *AESGCM = m_new_obj(mp_ciphers_aesgcm_t);
    AESGCM->base.type = &ciphers_aesgcm_type;
    AESGCM->key = vstr_new(bufinfo_key.len);
    vstr_add_strn(AESGCM->key, bufinfo_key.buf, bufinfo_key.len);

    return MP_OBJ_FROM_PTR(AESGCM);
#endif
}

static mp_obj_t aesgcm_generate_key(mp_obj_t bit_length)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    if (!mp_obj_is_int(bit_length))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected bit_length int"));
    }

    mp_int_t nbit = mp_obj_get_int(bit_length);
    if (nbit != 128 && nbit != 192 && nbit != 256)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("bit_length must be 128, 192 OR 256"));
    }

    vstr_t vstr_key;
    vstr_init_len(&vstr_key, nbit / 8);
    mp_random(NULL, (byte *)vstr_key.buf, vstr_key.len);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_key.buf, vstr_key.len);
    vstr_clear(&vstr_key);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_aesgcm_generate_key_obj, aesgcm_generate_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_aesgcm_generate_key_obj, MP_ROM_PTR(&mod_aesgcm_generate_key_obj));

static mp_obj_t aesgcm_encrypt(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;

    mp_ciphers_aesgcm_t *AESGCM = MP_OBJ_TO_PTR(args[0]);

    mp_buffer_info_t bufinfo_nonce;
    mp_get_buffer_raise(args[1], &bufinfo_nonce, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(args[2], &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_associated_data;
    bool use_associated_data = mp_get_buffer(args[3], &bufinfo_associated_data, MP_BUFFER_READ);

    vstr_t vstr_tag;
    vstr_init_len(&vstr_tag, 16);

    vstr_t vstr_output;
    vstr_init_len(&vstr_output, bufinfo_data.len);
    size_t olen = 0;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)AESGCM->key->buf, (AESGCM->key->len * 8));
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, bufinfo_nonce.buf, bufinfo_nonce.len);
    mbedtls_gcm_update_ad(&ctx, (use_associated_data ? bufinfo_associated_data.buf : NULL), (use_associated_data ? bufinfo_associated_data.len : 0));
    mbedtls_gcm_update(&ctx, bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_output.buf, vstr_output.len, &olen);
    mbedtls_gcm_finish(&ctx, (byte *)vstr_output.buf, vstr_output.len, &olen, (byte *)vstr_tag.buf, vstr_tag.len);
    mbedtls_gcm_free(&ctx);

    vstr_add_strn(&vstr_output, vstr_tag.buf, vstr_tag.len);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf, vstr_output.len);
    vstr_clear(&vstr_tag);
    vstr_clear(&vstr_output);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aesgcm_encrypt_obj, 4, 4, aesgcm_encrypt);

static mp_obj_t aesgcm_decrypt(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;

    mp_ciphers_aesgcm_t *AESGCM = MP_OBJ_TO_PTR(args[0]);

    mp_buffer_info_t bufinfo_nonce;
    mp_get_buffer_raise(args[1], &bufinfo_nonce, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(args[2], &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_associated_data;
    bool use_associated_data = mp_get_buffer(args[3], &bufinfo_associated_data, MP_BUFFER_READ);

    // PyCA AEAD appends a 16-byte authentication tag to the ciphertext.
    if (bufinfo_data.len < 16)
    {
        mp_raise_msg(&mp_type_InvalidTag, NULL);
    }

    size_t ciphertext_len = bufinfo_data.len - 16;
    const byte *tag = (const byte *)bufinfo_data.buf + ciphertext_len;

    vstr_t vstr_output;
    vstr_init_len(&vstr_output, ciphertext_len);

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)AESGCM->key->buf, (AESGCM->key->len * 8));
    int ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len,
                                       (const byte *)bufinfo_nonce.buf, bufinfo_nonce.len,
                                       (use_associated_data ? (const byte *)bufinfo_associated_data.buf : NULL), (use_associated_data ? bufinfo_associated_data.len : 0),
                                       tag, 16,
                                       (const byte *)bufinfo_data.buf, (byte *)vstr_output.buf);
    mbedtls_gcm_free(&ctx);

    if (ret != 0)
    {
        memset(vstr_output.buf, 0, vstr_output.len);
        vstr_clear(&vstr_output);
        mp_raise_msg(&mp_type_InvalidTag, NULL);
    }

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf, vstr_output.len);
    vstr_clear(&vstr_output);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aesgcm_decrypt_obj, 4, 4, aesgcm_decrypt);

static const mp_rom_map_elem_t aesgcm_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_generate_key), MP_ROM_PTR(&mod_static_aesgcm_generate_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_encrypt), MP_ROM_PTR(&mod_aesgcm_encrypt_obj)},
    {MP_ROM_QSTR(MP_QSTR_decrypt), MP_ROM_PTR(&mod_aesgcm_decrypt_obj)},
};

static MP_DEFINE_CONST_DICT(aesgcm_locals_dict, aesgcm_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_aesgcm_type,
    MP_QSTR_AESGCM,
    MP_TYPE_FLAG_NONE,
    make_new, aesgcm_make_new,
    locals_dict, &aesgcm_locals_dict);

static mp_obj_t cipher_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 2, 2, false);
    if (!mp_obj_is_type(args[0], &ciphers_algorithms_aes_type) && !mp_obj_is_type(args[0], &ciphers_algorithms_3des_type))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of algorithms.AES or algorithms.TripleDES"));
    }
    mp_ciphers_algorithms_t *algorithm = MP_OBJ_TO_PTR(args[0]);

    int mode_type = -1;

    if (mp_obj_is_type(args[1], &ciphers_modes_cbc_type))
    {
        mode_type = CIPHER_MODE_CBC;
    }
    else if (mp_obj_is_type(args[1], &ciphers_modes_gcm_type))
    {
        mode_type = CIPHER_MODE_GCM;
    }
    else if (mp_obj_is_type(args[1], &ciphers_modes_ecb_type))
    {
        mode_type = CIPHER_MODE_ECB;
    }
    else
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.CBC or modes.GCM or modes.ECB"));
    }

    mp_obj_t mode = args[1];

    mp_ciphers_cipher_t *cipher = m_new_obj(mp_ciphers_cipher_t);
    cipher->base.type = &ciphers_cipher_type;
    cipher->algorithm = algorithm;
    cipher->mode = mode;
    cipher->mode_type = mode_type;

    mp_ciphers_cipher_encryptor_t *encryptor = m_new_obj(mp_ciphers_cipher_encryptor_t);
    encryptor->base.type = &ciphers_cipher_encryptor_type;
    encryptor->data = vstr_new(0);
    encryptor->aadata = vstr_new(0);
    encryptor->finalized = false;
    encryptor->cipher = cipher;

    mp_ciphers_cipher_decryptor_t *decryptor = m_new_obj(mp_ciphers_cipher_decryptor_t);
    decryptor->base.type = &ciphers_cipher_decryptor_type;
    decryptor->data = vstr_new(0);
    decryptor->aadata = vstr_new(0);
    decryptor->finalized = false;
    decryptor->cipher = cipher;

    cipher->encryptor = encryptor;
    cipher->decryptor = decryptor;

    return MP_OBJ_FROM_PTR(cipher);
}

static mp_obj_t encryptor_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_ciphers_cipher_encryptor_t *encryptor = MP_OBJ_TO_PTR(self_in);
    vstr_clear(encryptor->data);
    vstr_clear(encryptor->aadata);
    encryptor->finalized = false;
    return MP_OBJ_FROM_PTR(encryptor);
}

static mp_obj_t encryptor_update(mp_obj_t self_o, mp_obj_t data)
{
    mp_ciphers_cipher_encryptor_t *self = MP_OBJ_TO_PTR(self_o);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (self->cipher->mode_type == CIPHER_MODE_CBC || self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        if (bufinfo_data.len % (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES ? 16 : 8))
        {
            mp_raise_ValueError(MP_ERROR_TEXT("The length of the provided data is not a multiple of the block length"));
        }
    }

    mp_int_t self_data_len = self->data->len;

    vstr_add_strn(self->data, bufinfo_data.buf, bufinfo_data.len);

    if (self->cipher->mode_type == CIPHER_MODE_CBC)
    {
        mp_ciphers_modes_cbc_t *mode = (mp_ciphers_modes_cbc_t *)MP_OBJ_TO_PTR(self->cipher->mode);

        vstr_t vstr_iv;
        vstr_init(&vstr_iv, 0);
        vstr_add_strn(&vstr_iv, mode->initialization_vector->buf, mode->initialization_vector->len);

        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);

        if (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_enc(&ctx, (byte *)self->cipher->algorithm->key->buf, self->cipher->algorithm->key->len * 8);
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, self->data->len, (byte *)vstr_iv.buf, (const byte *)self->data->buf, (byte *)vstr_output.buf);
            mbedtls_aes_free(&ctx);
        }
#ifdef MBEDTLS_DES_C
        else if (self->cipher->algorithm->type == CIPHER_ALGORITHM_3DES)
        {
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set3key_enc(&ctx, (byte *)self->cipher->algorithm->key->buf);
            mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, self->data->len, (byte *)vstr_iv.buf, (const byte *)self->data->buf, (byte *)vstr_output.buf);
            mbedtls_des3_free(&ctx);
        }
#endif

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_iv);
        vstr_clear(&vstr_output);
        return oo;
    }
    else if (self->cipher->mode_type == CIPHER_MODE_GCM)
    {
        mp_ciphers_modes_gcm_t *mode = (mp_ciphers_modes_gcm_t *)MP_OBJ_TO_PTR(self->cipher->mode);

        bool use_associated_data = self->aadata->buf != NULL && self->aadata->len;

        vstr_t vstr_iv;
        vstr_init(&vstr_iv, 0);
        vstr_add_strn(&vstr_iv, mode->initialization_vector->buf, mode->initialization_vector->len);

        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);
        size_t olen = 0;

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)self->cipher->algorithm->key->buf, (self->cipher->algorithm->key->len * 8));
        mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, (const byte *)vstr_iv.buf, vstr_iv.len);
        mbedtls_gcm_update_ad(&ctx, (use_associated_data ? (byte *)self->aadata->buf : NULL), (use_associated_data ? self->aadata->len : 0));
        mbedtls_gcm_update(&ctx, (const byte *)self->data->buf, self->data->len, (byte *)vstr_output.buf, vstr_output.len, &olen);
        mbedtls_gcm_finish(&ctx, (byte *)vstr_output.buf, vstr_output.len, &olen, (byte *)mode->tag->buf, mode->tag->len);
        mbedtls_gcm_free(&ctx);

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_iv);
        vstr_clear(&vstr_output);
        return oo;
    }
    else if (self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);

        if (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_enc(&ctx, (byte *)self->cipher->algorithm->key->buf, self->cipher->algorithm->key->len * 8);
            for (mp_uint_t i = 0; i < self->data->len; i += 16)
            {
                mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (const byte *)self->data->buf + i, (byte *)vstr_output.buf + i);
            }
            mbedtls_aes_free(&ctx);
        }
#ifdef MBEDTLS_DES_C
        else if (self->cipher->algorithm->type == CIPHER_ALGORITHM_3DES)
        {
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set3key_enc(&ctx, (byte *)self->cipher->algorithm->key->buf);
            for (mp_uint_t i = 0; i < self->data->len; i += 8)
            {
                mbedtls_des3_crypt_ecb(&ctx, (const byte *)self->data->buf + i, (byte *)vstr_output.buf + i);
            }
            mbedtls_des3_free(&ctx);
        }
#endif

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_output);
        return oo;
    }
    else
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.CBC or modes.GCM or modes.ECB"));
    }
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_encryptor_update_obj, encryptor_update);

static mp_obj_t encryptor_finalize(mp_obj_t self_o)
{
    mp_ciphers_cipher_encryptor_t *self = MP_OBJ_TO_PTR(self_o);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }
    self->finalized = true;
    return mp_const_empty_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_encryptor_finalize_obj, encryptor_finalize);

static mp_obj_t encryptor_authenticate_additional_data(mp_obj_t self_o, mp_obj_t aadata)
{
    mp_ciphers_cipher_encryptor_t *self = MP_OBJ_TO_PTR(self_o);
    if (self->cipher->mode_type == CIPHER_MODE_CBC || self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.GCM"));
    }

    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_aadata;
    mp_get_buffer_raise(aadata, &bufinfo_aadata, MP_BUFFER_READ);

    vstr_clear(self->aadata);
    vstr_add_strn(self->aadata, bufinfo_aadata.buf, bufinfo_aadata.len);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_encryptor_authenticate_additional_data_obj, encryptor_authenticate_additional_data);

static void encryptpr_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ciphers_cipher_encryptor_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_tag)
            {
                if (self->cipher->mode_type == CIPHER_MODE_CBC || self->cipher->mode_type == CIPHER_MODE_ECB)
                {
                    mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.GCM"));
                }

                if (!self->finalized)
                {
                    mp_raise_msg(&mp_type_NotYetFinalized, NULL);
                }

                mp_ciphers_modes_gcm_t *mode = (mp_ciphers_modes_gcm_t *)MP_OBJ_TO_PTR(self->cipher->mode);
                dest[0] = mp_obj_new_bytes((const byte *)mode->tag->buf, mode->tag->len);
                return;
            }

            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t encryptor_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&mod_encryptor_update_obj)},
    {MP_ROM_QSTR(MP_QSTR_finalize), MP_ROM_PTR(&mod_encryptor_finalize_obj)},
    {MP_ROM_QSTR(MP_QSTR_authenticate_additional_data), MP_ROM_PTR(&mod_encryptor_authenticate_additional_data_obj)},
    {MP_ROM_QSTR(MP_QSTR_tag), MP_ROM_PTR(mp_const_none)},
};

static MP_DEFINE_CONST_DICT(encryptor_locals_dict, encryptor_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_cipher_encryptor_type,
    MP_QSTR_encryptor,
    MP_TYPE_FLAG_NONE,
    call, encryptor_call,
    attr, encryptpr_attr,
    locals_dict, &encryptor_locals_dict);

static mp_obj_t decryptor_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_ciphers_cipher_decryptor_t *decryptor = MP_OBJ_TO_PTR(self_in);
    vstr_clear(decryptor->data);
    vstr_clear(decryptor->aadata);
    decryptor->finalized = false;
    return MP_OBJ_FROM_PTR(decryptor);
}

static mp_obj_t decryptor_update(mp_obj_t self_o, mp_obj_t data)
{
    mp_ciphers_cipher_decryptor_t *self = MP_OBJ_TO_PTR(self_o);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

    if (self->cipher->mode_type == CIPHER_MODE_CBC || self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        if (bufinfo_data.len % (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES ? 16 : 8))
        {
            mp_raise_ValueError(MP_ERROR_TEXT("The length of the provided data is not a multiple of the block length"));
        }
    }

    mp_int_t self_data_len = self->data->len;
    vstr_add_strn(self->data, bufinfo_data.buf, bufinfo_data.len);

    if (self->cipher->mode_type == CIPHER_MODE_CBC)
    {
        mp_ciphers_modes_cbc_t *mode = (mp_ciphers_modes_cbc_t *)MP_OBJ_TO_PTR(self->cipher->mode);

        vstr_t vstr_iv;
        vstr_init(&vstr_iv, 0);
        vstr_add_strn(&vstr_iv, mode->initialization_vector->buf, mode->initialization_vector->len);

        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);

        if (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_dec(&ctx, (byte *)self->cipher->algorithm->key->buf, self->cipher->algorithm->key->len * 8);
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, self->data->len, (byte *)vstr_iv.buf, (const byte *)self->data->buf, (byte *)vstr_output.buf);
            mbedtls_aes_free(&ctx);
        }
#ifdef MBEDTLS_DES_C
        else if (self->cipher->algorithm->type == CIPHER_ALGORITHM_3DES)
        {
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set3key_dec(&ctx, (byte *)self->cipher->algorithm->key->buf);
            mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, self->data->len, (byte *)vstr_iv.buf, (const byte *)self->data->buf, (byte *)vstr_output.buf);
            mbedtls_des3_free(&ctx);
        }
#endif

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_iv);
        vstr_clear(&vstr_output);
        return oo;
    }
    else if (self->cipher->mode_type == CIPHER_MODE_GCM)
    {
        mp_ciphers_modes_gcm_t *mode = (mp_ciphers_modes_gcm_t *)MP_OBJ_TO_PTR(self->cipher->mode);

        bool use_associated_data = self->aadata->buf != NULL && self->aadata->len;

        vstr_t vstr_iv;
        vstr_init(&vstr_iv, 0);
        vstr_add_strn(&vstr_iv, mode->initialization_vector->buf, mode->initialization_vector->len);

        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);
        size_t olen = 0;

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)self->cipher->algorithm->key->buf, (self->cipher->algorithm->key->len * 8));
        mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, (const byte *)vstr_iv.buf, vstr_iv.len);
        mbedtls_gcm_update_ad(&ctx, (use_associated_data ? (byte *)self->aadata->buf : NULL), (use_associated_data ? self->aadata->len : 0));
        mbedtls_gcm_update(&ctx, (const byte *)self->data->buf, self->data->len, (byte *)vstr_output.buf, vstr_output.len, &olen);
        // Discard the computed tag: the caller-supplied expected tag (mode->tag) is authenticated in finalize().
        byte computed_tag[16];
        mbedtls_gcm_finish(&ctx, (byte *)vstr_output.buf, vstr_output.len, &olen, computed_tag, sizeof(computed_tag));
        mbedtls_gcm_free(&ctx);

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_iv);
        vstr_clear(&vstr_output);
        return oo;
    }
    else if (self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);

        if (self->cipher->algorithm->type == CIPHER_ALGORITHM_AES)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_dec(&ctx, (byte *)self->cipher->algorithm->key->buf, self->cipher->algorithm->key->len * 8);
            for (mp_uint_t i = 0; i < self->data->len; i += 16)
            {
                mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, (const byte *)self->data->buf + i, (byte *)vstr_output.buf + i);
            }
            mbedtls_aes_free(&ctx);
        }
#ifdef MBEDTLS_DES_C
        else if (self->cipher->algorithm->type == CIPHER_ALGORITHM_3DES)
        {
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set3key_dec(&ctx, (byte *)self->cipher->algorithm->key->buf);
            for (mp_uint_t i = 0; i < self->data->len; i += 8)
            {
                mbedtls_des3_crypt_ecb(&ctx, (const byte *)self->data->buf + i, (byte *)vstr_output.buf + i);
            }
            mbedtls_des3_free(&ctx);
        }
#endif

        mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf + self_data_len, vstr_output.len - self_data_len);
        vstr_clear(&vstr_output);
        return oo;
    }
    else
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.CBC or modes.GCM or modes.ECB"));
    }
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_decryptor_update_obj, decryptor_update);

static mp_obj_t decryptor_finalize(mp_obj_t self_o)
{
    mp_ciphers_cipher_decryptor_t *self = MP_OBJ_TO_PTR(self_o);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    if (self->cipher->mode_type == CIPHER_MODE_GCM)
    {
        mp_ciphers_modes_gcm_t *mode = (mp_ciphers_modes_gcm_t *)MP_OBJ_TO_PTR(self->cipher->mode);
        if (!mode->has_tag)
        {
            self->finalized = true;
            mp_raise_ValueError(MP_ERROR_TEXT("Authentication tag must be provided when decrypting"));
        }

        // Authenticate the whole buffered ciphertext against the expected tag; fail closed on mismatch.
        bool use_associated_data = self->aadata->buf != NULL && self->aadata->len;
        vstr_t vstr_output;
        vstr_init_len(&vstr_output, self->data->len);

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)self->cipher->algorithm->key->buf, (self->cipher->algorithm->key->len * 8));
        int ret = mbedtls_gcm_auth_decrypt(&ctx, self->data->len,
                                           (const byte *)mode->initialization_vector->buf, mode->initialization_vector->len,
                                           (use_associated_data ? (const byte *)self->aadata->buf : NULL), (use_associated_data ? self->aadata->len : 0),
                                           (const byte *)mode->tag->buf, mode->tag->len,
                                           (const byte *)self->data->buf, (byte *)vstr_output.buf);
        mbedtls_gcm_free(&ctx);
        memset(vstr_output.buf, 0, vstr_output.len);
        vstr_clear(&vstr_output);

        if (ret != 0)
        {
            self->finalized = true;
            mp_raise_msg(&mp_type_InvalidTag, NULL);
        }
    }

    self->finalized = true;
    return mp_const_empty_bytes;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_decryptor_finalize_obj, decryptor_finalize);

static mp_obj_t decryptor_authenticate_additional_data(mp_obj_t self_o, mp_obj_t aadata)
{
    mp_ciphers_cipher_decryptor_t *self = MP_OBJ_TO_PTR(self_o);

    if (self->cipher->mode_type == CIPHER_MODE_CBC || self->cipher->mode_type == CIPHER_MODE_ECB)
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected Instance of modes.GCM"));
    }

    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_aadata;
    mp_get_buffer_raise(aadata, &bufinfo_aadata, MP_BUFFER_READ);

    vstr_add_strn(self->aadata, bufinfo_aadata.buf, bufinfo_aadata.len);

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_decryptor_authenticate_additional_data_obj, decryptor_authenticate_additional_data);

static const mp_rom_map_elem_t decryptor_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&mod_decryptor_update_obj)},
    {MP_ROM_QSTR(MP_QSTR_finalize), MP_ROM_PTR(&mod_decryptor_finalize_obj)},
    {MP_ROM_QSTR(MP_QSTR_authenticate_additional_data), MP_ROM_PTR(&mod_decryptor_authenticate_additional_data_obj)},
};

static MP_DEFINE_CONST_DICT(decryptor_locals_dict, decryptor_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_cipher_decryptor_type,
    MP_QSTR_decryptor,
    MP_TYPE_FLAG_NONE,
    call, decryptor_call,
    locals_dict, &decryptor_locals_dict);

static void cipher_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ciphers_cipher_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        const mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = (mp_map_t *)mp_obj_dict_get_map(MP_OBJ_TYPE_GET_SLOT(type, locals_dict));
        mp_map_elem_t *elem = mp_map_lookup(locals_map, MP_OBJ_NEW_QSTR(attr), MP_MAP_LOOKUP);
        if (elem != NULL)
        {
            if (attr == MP_QSTR_encryptor)
            {
                dest[0] = self->encryptor;
                return;
            }
            if (attr == MP_QSTR_decryptor)
            {
                dest[0] = self->decryptor;
                return;
            }
            mp_convert_member_lookup(obj, type, elem->value, dest);
        }
    }
}

static const mp_rom_map_elem_t ciphers_cipher_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_encryptor), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_decryptor), MP_ROM_PTR(mp_const_none)},
};

static MP_DEFINE_CONST_DICT(ciphers_cipher_locals_dict, ciphers_cipher_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_cipher_type,
    MP_QSTR_Cipher,
    MP_TYPE_FLAG_NONE,
    make_new, cipher_make_new,
    attr, cipher_attr,
    locals_dict, &ciphers_cipher_locals_dict);

static mp_obj_t algorithms_aes_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_AES
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("AES disabled (enable MICROPY_PY_UCRYPTOGRAPHY_AES)"));
#else
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_obj_t key = args[0];

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(key, &bufinfo_key, MP_BUFFER_READ);

    mp_ciphers_algorithms_t *CIPHER_ALGORITHM = m_new_obj(mp_ciphers_algorithms_t);
    CIPHER_ALGORITHM->base.type = &ciphers_algorithms_aes_type;
    CIPHER_ALGORITHM->key = vstr_new(bufinfo_key.len);
    vstr_add_strn(CIPHER_ALGORITHM->key, bufinfo_key.buf, bufinfo_key.len);
    CIPHER_ALGORITHM->type = CIPHER_ALGORITHM_AES;

    return MP_OBJ_FROM_PTR(CIPHER_ALGORITHM);
#endif
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_algorithms_aes_type,
    MP_QSTR_AES,
    MP_TYPE_FLAG_NONE,
    make_new, algorithms_aes_make_new);

static mp_obj_t algorithms_3des_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_TRIPLEDES
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("TripleDES disabled (enable MICROPY_PY_UCRYPTOGRAPHY_TRIPLEDES)"));
#else
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_obj_t key = args[0];

    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(key, &bufinfo, MP_BUFFER_READ);

    mp_ciphers_algorithms_t *CIPHER_ALGORITHM = m_new_obj(mp_ciphers_algorithms_t);
    CIPHER_ALGORITHM->base.type = &ciphers_algorithms_3des_type;
    CIPHER_ALGORITHM->key = vstr_new(bufinfo.len);
    vstr_add_strn(CIPHER_ALGORITHM->key, bufinfo.buf, bufinfo.len);
    CIPHER_ALGORITHM->type = CIPHER_ALGORITHM_3DES;

    return MP_OBJ_FROM_PTR(CIPHER_ALGORITHM);
#endif
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_algorithms_3des_type,
    MP_QSTR_TripleDES,
    MP_TYPE_FLAG_NONE,
    make_new, algorithms_3des_make_new);

static const mp_rom_map_elem_t ciphers_algorithms_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_AES), MP_ROM_PTR(&ciphers_algorithms_aes_type)},
    {MP_ROM_QSTR(MP_QSTR_TripleDES), MP_ROM_PTR(&ciphers_algorithms_3des_type)},
};

static MP_DEFINE_CONST_DICT(ciphers_algorithms_locals_dict, ciphers_algorithms_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_algorithms_type,
    MP_QSTR_algorithms,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ciphers_algorithms_locals_dict);

static mp_obj_t modes_cbc_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_buffer_info_t bufinfo_iv;
    mp_get_buffer_raise(args[0], &bufinfo_iv, MP_BUFFER_READ);

    if (bufinfo_iv.len != 16 && bufinfo_iv.len != 8)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid IV size for CBC"));
    }

    mp_ciphers_modes_cbc_t *CBC = m_new_obj(mp_ciphers_modes_cbc_t);
    CBC->base.type = &ciphers_modes_cbc_type;
    CBC->initialization_vector = vstr_new(bufinfo_iv.len);
    vstr_add_strn(CBC->initialization_vector, bufinfo_iv.buf, bufinfo_iv.len);

    return MP_OBJ_FROM_PTR(CBC);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_modes_cbc_type,
    MP_QSTR_CBC,
    MP_TYPE_FLAG_NONE,
    make_new, modes_cbc_make_new);

static mp_obj_t modes_gcm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
    mp_arg_check_num(n_args, n_kw, 1, 3, true);
    enum
    {
        ARG_initialization_vector,
        ARG_tag,
        ARG_min_tag_length
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_initialization_vector, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_tag, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_min_tag_length, MP_ARG_KW_ONLY | MP_ARG_INT, {.u_int = 16}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_buffer_info_t bufinfo_iv;
    mp_get_buffer_raise(args[ARG_initialization_vector].u_obj, &bufinfo_iv, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_tag;
    bool has_tag = args[ARG_tag].u_obj != MP_OBJ_NULL && mp_get_buffer(args[ARG_tag].u_obj, &bufinfo_tag, MP_BUFFER_READ);

    mp_ciphers_modes_gcm_t *GCM = m_new_obj(mp_ciphers_modes_gcm_t);
    GCM->base.type = &ciphers_modes_gcm_type;
    GCM->initialization_vector = vstr_new(bufinfo_iv.len);
    vstr_add_strn(GCM->initialization_vector, bufinfo_iv.buf, bufinfo_iv.len);
    GCM->min_tag_length = (args[ARG_min_tag_length].u_int < 16 ? 16 : args[ARG_min_tag_length].u_int);
    GCM->tag = vstr_new(GCM->min_tag_length);
    if (has_tag)
    {
        // Reject truncated tags (PyCA contract): a supplied tag shorter than
        // min_tag_length would silently weaken authentication.
        if ((mp_int_t)bufinfo_tag.len < GCM->min_tag_length)
        {
            mp_raise_ValueError(MP_ERROR_TEXT("Authentication tag must be min_tag_length bytes or longer"));
        }
        vstr_add_strn(GCM->tag, bufinfo_tag.buf, bufinfo_tag.len);
    }
    else
    {
        GCM->tag->len = GCM->min_tag_length;
    }
    GCM->has_tag = has_tag;

    return MP_OBJ_FROM_PTR(GCM);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_modes_gcm_type,
    MP_QSTR_GCM,
    MP_TYPE_FLAG_NONE,
    make_new, modes_gcm_make_new);

static mp_obj_t modes_ecb_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 0, false);

    mp_ciphers_modes_ecb_t *ECB = m_new_obj(mp_ciphers_modes_ecb_t);
    ECB->base.type = &ciphers_modes_ecb_type;

    return MP_OBJ_FROM_PTR(ECB);
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_modes_ecb_type,
    MP_QSTR_ECB,
    MP_TYPE_FLAG_NONE,
    make_new, modes_ecb_make_new);

static const mp_rom_map_elem_t ciphers_modes_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_CBC), MP_ROM_PTR(&ciphers_modes_cbc_type)},
    {MP_ROM_QSTR(MP_QSTR_GCM), MP_ROM_PTR(&ciphers_modes_gcm_type)},
    {MP_ROM_QSTR(MP_QSTR_ECB), MP_ROM_PTR(&ciphers_modes_ecb_type)},
};

static MP_DEFINE_CONST_DICT(ciphers_modes_locals_dict, ciphers_modes_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_modes_type,
    MP_QSTR_modes,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ciphers_modes_locals_dict);

static mp_obj_t twofactor_otp_generate(mp_obj_t self_obj, mp_obj_t counter_obj)
{
    mp_obj_t _key = mp_const_none;
    mp_int_t _md_type = 0;
    mp_int_t _length = 0;
    if (mp_obj_is_type(self_obj, &twofactor_hotp_type))
    {
        mp_twofactor_hotp_t *self = MP_OBJ_TO_PTR(self_obj);
        _key = self->key;
        _md_type = self->algorithm->md_type;
        _length = self->length;
    }
    else if (mp_obj_is_type(self_obj, &twofactor_totp_type))
    {
        mp_twofactor_totp_t *self = MP_OBJ_TO_PTR(self_obj);
        _key = self->key;
        _md_type = self->algorithm->md_type;
        _length = self->length;
    }

    if (!mp_obj_is_int(counter_obj))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("int required, got %s"), mp_obj_get_type_str(counter_obj)));
    }

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(_key, &bufinfo_key, MP_BUFFER_READ);

    mp_obj_t counter = cryptography_small_to_big_int(counter_obj);
    vstr_t vstr_counter;
    vstr_init_len(&vstr_counter, sizeof(unsigned long long));
    mp_obj_int_to_bytes(counter, vstr_counter.len, (byte *)vstr_counter.buf, true, false, false);

    vstr_t vstr_hmac_value;
    vstr_init_len(&vstr_hmac_value, mbedtls_md_get_size(mbedtls_md_info_from_type(_md_type)));
    mbedtls_md_hmac(mbedtls_md_info_from_type(_md_type), (const byte *)bufinfo_key.buf, bufinfo_key.len, (const byte *)vstr_counter.buf, vstr_counter.len, (byte *)vstr_hmac_value.buf);

    byte offset = vstr_hmac_value.buf[vstr_hmac_value.len - 1] & 0b1111;

    mpz_t p;
    mpz_init_zero(&p);
    mpz_set_from_bytes(&p, true, 4, (const byte *)vstr_hmac_value.buf + offset);

    mpz_t mask;
    mpz_init_from_int(&mask, 0x7FFFFFFF);

    mpz_t truncated_value;
    mpz_init_zero(&truncated_value);
    mpz_and_inpl(&truncated_value, &p, &mask);
    mpz_deinit(&p);
    mpz_deinit(&mask);

    mpz_t ten;
    mpz_init_from_int(&ten, 10);

    mpz_t length;
    mpz_init_from_int(&length, _length);

    mpz_t ten_pow_length;
    mpz_init_zero(&ten_pow_length);

    mpz_pow_inpl(&ten_pow_length, &ten, &length);

    mpz_deinit(&ten);
    mpz_deinit(&length);

    mpz_t quo;
    mpz_init_zero(&quo);
    mp_obj_int_t *hotp = mp_obj_int_new_mpz();

    mpz_divmod_inpl(&quo, &hotp->mpz, &truncated_value, &ten_pow_length);

    mpz_deinit(&truncated_value);
    mpz_deinit(&quo);
    mpz_deinit(&ten_pow_length);

    vstr_clear(&vstr_counter);
    vstr_clear(&vstr_hmac_value);

    vstr_t *vstr = vstr_new_from_mpz(&hotp->mpz);
    while ((mp_int_t)vstr_len(vstr) < _length)
    {
        vstr_ins_char(vstr, 0, '0');
    }
    return mp_obj_new_bytes_from_vstr(vstr);
}

static mp_obj_t twofactor_hotp_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)all_args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("twofactor disabled (enable MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR)"));
#else
    mp_arg_check_num(n_args, n_kw, 3, 4, false);
    enum
    {
        ARG_key,
        ARG_length,
        ARG_algorithm,
        ARG_enforce_key_length
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_key, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_length, MP_ARG_INT, {.u_int = 6}},
        {MP_QSTR_algorithm, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_enforce_key_length, MP_ARG_BOOL, {.u_bool = mp_const_true}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(args[ARG_key].u_obj, &bufinfo_key, MP_BUFFER_READ);

    bool enforce_key_length = args[ARG_enforce_key_length].u_bool;
    if (bufinfo_key.len < 16 && enforce_key_length)
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Key length has to be at least 128 bits."));
    }

    mp_int_t length = args[ARG_length].u_int;
    if (length < 6 || length > 8)
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Length of HOTP has to be between 6 to 8."));
    }

    mp_obj_t hash_algorithm = args[ARG_algorithm].u_obj;
    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("Algorithm must be SHA1, SHA256 or SHA512."));
    }

    mp_twofactor_hotp_t *HOTP = m_new_obj(mp_twofactor_hotp_t);
    HOTP->base.type = &twofactor_hotp_type;
    HOTP->key = mp_obj_new_bytes((const byte *)bufinfo_key.buf, bufinfo_key.len);
    HOTP->length = length;
    HOTP->algorithm = hash_algorithm;
    HOTP->enforce_key_length = enforce_key_length;

    return MP_OBJ_FROM_PTR(HOTP);
#endif
}

static mp_obj_t twofactor_hotp_generate(mp_obj_t self_obj, mp_obj_t counter_obj)
{
    mp_twofactor_hotp_t *self = MP_OBJ_TO_PTR(self_obj);
    return twofactor_otp_generate(self, counter_obj);
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_twofactor_hotp_generate_obj, twofactor_hotp_generate);

static mp_obj_t twofactor_hotp_verify(mp_obj_t self_obj, mp_obj_t hotp_obj, mp_obj_t counter_obj)
{
    mp_obj_t hotp = hotp_obj;
    if (!mp_obj_is_int(hotp))
    {
        mp_buffer_info_t bufinfo_hotp;
        cryptography_get_buffer(hotp, true, &bufinfo_hotp);
        hotp = mp_obj_new_int_from_str_len((const char **)&bufinfo_hotp.buf, bufinfo_hotp.len, false, 10);
    }

    if (!mp_obj_is_int(hotp))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("int required, got %s"), mp_obj_get_type_str(hotp)));
    }

    mp_twofactor_hotp_t *self = MP_OBJ_TO_PTR(self_obj);
    mp_obj_t hotp_value = twofactor_hotp_generate(self, counter_obj);
    mp_buffer_info_t bufinfo_hotp_value;
    cryptography_get_buffer(hotp_value, true, &bufinfo_hotp_value);
    hotp_value = mp_obj_new_int_from_str_len((const char **)&bufinfo_hotp_value.buf, bufinfo_hotp_value.len, false, 10);

    // Constant-time comparison of the two OTP values (serialized big-endian).
    byte buf_generated[8] = {0};
    byte buf_supplied[8] = {0};
    mp_obj_int_to_bytes(hotp_value, sizeof(buf_generated), buf_generated, true, false, false);
    mp_obj_int_to_bytes(hotp, sizeof(buf_supplied), buf_supplied, true, false, false);
    if (!constant_time_bytes_eq(buf_generated, sizeof(buf_generated), buf_supplied, sizeof(buf_supplied)))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Supplied HOTP value does not match."));
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_twofactor_hotp_verify_obj, twofactor_hotp_verify);

static mp_obj_t twofactor_hotp_get_provisioning_uri(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT(""));
    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_twofactor_hotp_get_provisioning_uri_obj, 4, 4, twofactor_hotp_get_provisioning_uri);

static const mp_rom_map_elem_t twofactor_hotp_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_generate), MP_ROM_PTR(&mod_twofactor_hotp_generate_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&mod_twofactor_hotp_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_provisioning_uri), MP_ROM_PTR(&mod_twofactor_hotp_get_provisioning_uri_obj)},
};

static MP_DEFINE_CONST_DICT(twofactor_hotp_locals_dict, twofactor_hotp_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    twofactor_hotp_type,
    MP_QSTR_HOTP,
    MP_TYPE_FLAG_NONE,
    make_new, twofactor_hotp_make_new,
    locals_dict, &twofactor_hotp_locals_dict);

static mp_obj_t twofactor_totp_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
#if !MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)all_args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("twofactor disabled (enable MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR)"));
#else
    mp_arg_check_num(n_args, n_kw, 4, 5, false);
    enum
    {
        ARG_key,
        ARG_length,
        ARG_algorithm,
        ARG_time_step,
        ARG_enforce_key_length
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_key, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_length, MP_ARG_INT, {.u_int = 6}},
        {MP_QSTR_algorithm, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_time_step, MP_ARG_INT, {.u_int = 30}},
        {MP_QSTR_enforce_key_length, MP_ARG_BOOL, {.u_bool = mp_const_true}},
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(args[ARG_key].u_obj, &bufinfo_key, MP_BUFFER_READ);

    bool enforce_key_length = args[ARG_enforce_key_length].u_bool;
    if (bufinfo_key.len < 16 && enforce_key_length)
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Key length has to be at least 128 bits."));
    }

    mp_int_t length = args[ARG_length].u_int;
    if (length < 6 || length > 8)
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Length of HOTP has to be between 6 to 8."));
    }

    mp_obj_t hash_algorithm = args[ARG_algorithm].u_obj;
    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("Algorithm must be SHA1, SHA256 or SHA512."));
    }

    mp_int_t time_step = args[ARG_time_step].u_int;

    mp_twofactor_totp_t *TOTP = m_new_obj(mp_twofactor_totp_t);
    TOTP->base.type = &twofactor_totp_type;
    TOTP->key = mp_obj_new_bytes((const byte *)bufinfo_key.buf, bufinfo_key.len);
    TOTP->length = length;
    TOTP->algorithm = hash_algorithm;
    TOTP->time_step = time_step;
    TOTP->enforce_key_length = enforce_key_length;

    return MP_OBJ_FROM_PTR(TOTP);
#endif
}

static mp_obj_t twofactor_totp_generate(mp_obj_t self_obj, mp_obj_t time_obj)
{
    if (!mp_obj_is_int(time_obj))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("int required, got %s"), mp_obj_get_type_str(time_obj)));
    }
    mp_twofactor_totp_t *self = MP_OBJ_TO_PTR(self_obj);
    mp_int_t counter = (mp_int_t)(mp_obj_get_int(time_obj) / self->time_step);
    return twofactor_otp_generate(self, mp_obj_new_int(counter));
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_twofactor_totp_generate_obj, twofactor_totp_generate);

static mp_obj_t twofactor_totp_verify(mp_obj_t self_obj, mp_obj_t totp_obj, mp_obj_t time_obj)
{
    mp_obj_t totp = totp_obj;
    if (!mp_obj_is_int(totp))
    {
        mp_buffer_info_t bufinfo_totp;
        cryptography_get_buffer(totp, true, &bufinfo_totp);
        totp = mp_obj_new_int_from_str_len((const char **)&bufinfo_totp.buf, bufinfo_totp.len, false, 10);
    }

    if (!mp_obj_is_int(totp))
    {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError, MP_ERROR_TEXT("int required, got %s"), mp_obj_get_type_str(totp)));
    }

    mp_twofactor_totp_t *self = MP_OBJ_TO_PTR(self_obj);
    mp_obj_t hotp_value = twofactor_totp_generate(self, time_obj);
    mp_buffer_info_t bufinfo_hotp_value;
    cryptography_get_buffer(hotp_value, true, &bufinfo_hotp_value);
    hotp_value = mp_obj_new_int_from_str_len((const char **)&bufinfo_hotp_value.buf, bufinfo_hotp_value.len, false, 10);

    // Constant-time comparison of the two OTP values (serialized big-endian).
    byte buf_generated[8] = {0};
    byte buf_supplied[8] = {0};
    mp_obj_int_to_bytes(hotp_value, sizeof(buf_generated), buf_generated, true, false, false);
    mp_obj_int_to_bytes(totp, sizeof(buf_supplied), buf_supplied, true, false, false);
    if (!constant_time_bytes_eq(buf_generated, sizeof(buf_generated), buf_supplied, sizeof(buf_supplied)))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Supplied HOTP value does not match."));
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_twofactor_totp_verify_obj, twofactor_totp_verify);

static mp_obj_t twofactor_totp_get_provisioning_uri(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT(""));
    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_twofactor_totp_get_provisioning_uri_obj, 4, 4, twofactor_totp_get_provisioning_uri);

static const mp_rom_map_elem_t twofactor_totp_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_generate), MP_ROM_PTR(&mod_twofactor_totp_generate_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&mod_twofactor_totp_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_provisioning_uri), MP_ROM_PTR(&mod_twofactor_totp_get_provisioning_uri_obj)},
};

static MP_DEFINE_CONST_DICT(twofactor_totp_locals_dict, twofactor_totp_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    twofactor_totp_type,
    MP_QSTR_TOTP,
    MP_TYPE_FLAG_NONE,
    make_new, twofactor_totp_make_new,
    locals_dict, &twofactor_totp_locals_dict);

static mp_obj_t _bits2int(mp_util_rfc6979_t *self, mp_obj_t b_obj)
{
    mp_buffer_info_t bufinfo_b;
    mp_get_buffer_raise(b_obj, &bufinfo_b, MP_BUFFER_READ);
    mp_obj_int_t *i = cryptography_small_to_big_int(mp_obj_int_from_bytes_impl(true, bufinfo_b.len, (const byte *)bufinfo_b.buf));
    mp_int_t blen = bufinfo_b.len * 8;
    if (blen > self->qlen)
    {
        mpz_shr_inpl(&i->mpz, &i->mpz, (blen - self->qlen));
    }
    return i;
}

static mp_obj_t _int2octets(mp_util_rfc6979_t *self, mp_obj_t x_obj)
{
    mp_buffer_info_t bufinfo_octets;
    cryptography_get_buffer(x_obj, true, &bufinfo_octets);

    vstr_t padding_octets_vstr;
    vstr_init(&padding_octets_vstr, ((self->rlen / 8) - bufinfo_octets.len));
    for (mp_uint_t i = 0; i < ((self->rlen / 8) - bufinfo_octets.len); i++)
    {
        vstr_add_byte(&padding_octets_vstr, 0x00);
    }
    vstr_add_strn(&padding_octets_vstr, bufinfo_octets.buf, bufinfo_octets.len);

    mp_obj_t oo = mp_obj_new_bytes((byte *)padding_octets_vstr.buf, padding_octets_vstr.len);
    vstr_clear(&padding_octets_vstr);
    return oo;
}

static mp_obj_t _bits2octets(mp_util_rfc6979_t *self, mp_obj_t b_obj)
{
    mp_obj_int_t *z1 = cryptography_small_to_big_int(_bits2int(self, b_obj));
    mp_obj_int_t *q = cryptography_small_to_big_int(self->q);

    mpz_t quo;
    mpz_init_zero(&quo);

    mp_obj_int_t *z2 = mp_obj_int_new_mpz();
    mpz_divmod_inpl(&quo, &z2->mpz, &z1->mpz, &q->mpz);

    mpz_deinit(&quo);

    mp_obj_t z2o = _int2octets(self, z2);
    return z2o;
}

static mp_obj_t utils_rfc6979_gen_nonce(mp_obj_t self_obj)
{
    mp_util_rfc6979_t *self = MP_OBJ_TO_PTR(self_obj);

    mp_buffer_info_t bufinfo_msg;
    mp_get_buffer_raise(self->msg, &bufinfo_msg, MP_BUFFER_READ);

    mp_hash_algorithm_t *algorithm = MP_OBJ_TO_PTR(self->algorithm);
    mp_int_t hash_size = mbedtls_md_get_size(mbedtls_md_info_from_type(algorithm->md_type));

    vstr_t vstr_h1;
    vstr_init_len(&vstr_h1, hash_size);
    mbedtls_md(mbedtls_md_info_from_type(algorithm->md_type), (const byte *)bufinfo_msg.buf, bufinfo_msg.len, (byte *)vstr_h1.buf);

    mp_buffer_info_t bufinfo_key_octets;
    mp_get_buffer_raise(_int2octets(self, self->x), &bufinfo_key_octets, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_msg_octets;
    mp_get_buffer_raise(_bits2octets(self, mp_obj_new_bytes((byte *)vstr_h1.buf, vstr_h1.len)), &bufinfo_msg_octets, MP_BUFFER_READ);

    vstr_t vstr_key_and_msg;
    vstr_init(&vstr_key_and_msg, bufinfo_key_octets.len + bufinfo_msg_octets.len);
    vstr_add_strn(&vstr_key_and_msg, bufinfo_key_octets.buf, bufinfo_key_octets.len);
    vstr_add_strn(&vstr_key_and_msg, bufinfo_msg_octets.buf, bufinfo_msg_octets.len);

    vstr_t vstr_v;
    vstr_init(&vstr_v, hash_size);
    for (mp_int_t i = 0; i < hash_size; i++)
    {
        vstr_add_byte(&vstr_v, 0x01);
    }

    vstr_t vstr_k;
    vstr_init(&vstr_k, hash_size);
    for (mp_int_t i = 0; i < hash_size; i++)
    {
        vstr_add_byte(&vstr_k, 0x00);
    }

    vstr_t vstr_v_00_key_and_msg;
    vstr_init(&vstr_v_00_key_and_msg, vstr_v.len + 1 + vstr_key_and_msg.len);
    vstr_add_strn(&vstr_v_00_key_and_msg, vstr_v.buf, vstr_v.len);
    vstr_add_byte(&vstr_v_00_key_and_msg, 0x00);
    vstr_add_strn(&vstr_v_00_key_and_msg, vstr_key_and_msg.buf, vstr_key_and_msg.len);

    mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v_00_key_and_msg.buf, vstr_v_00_key_and_msg.len, (byte *)vstr_k.buf);

    mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v.buf, vstr_v.len, (byte *)vstr_v.buf);

    vstr_t vstr_v_01_key_and_msg;
    vstr_init(&vstr_v_01_key_and_msg, vstr_v.len + 1 + vstr_key_and_msg.len);
    vstr_add_strn(&vstr_v_01_key_and_msg, vstr_v.buf, vstr_v.len);
    vstr_add_byte(&vstr_v_01_key_and_msg, 0x01);
    vstr_add_strn(&vstr_v_01_key_and_msg, vstr_key_and_msg.buf, vstr_key_and_msg.len);

    mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v_01_key_and_msg.buf, vstr_v_01_key_and_msg.len, (byte *)vstr_k.buf);

    mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v.buf, vstr_v.len, (byte *)vstr_v.buf);

    mp_obj_int_t *q = cryptography_small_to_big_int(self->q);

    mpz_t one;
    mpz_init_from_int(&one, 1);

    while (true)
    {
        vstr_t vstr_temp;
        vstr_init(&vstr_temp, 0);

        while ((mp_int_t)(vstr_temp.len * 8) < self->qlen)
        {
            mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v.buf, vstr_v.len, (byte *)vstr_v.buf);
            vstr_add_strn(&vstr_temp, vstr_v.buf, vstr_v.len);
        }

        mp_obj_int_t *nonce = cryptography_small_to_big_int(_bits2int(self, mp_obj_new_bytes((byte *)vstr_temp.buf, vstr_temp.len)));
        if (mpz_cmp(&nonce->mpz, &one) >= 0 && mpz_cmp(&nonce->mpz, &q->mpz) < 0)
        {
            mpz_deinit(&one);
            vstr_clear(&vstr_h1);
            vstr_clear(&vstr_key_and_msg);
            vstr_clear(&vstr_v);
            vstr_clear(&vstr_k);
            vstr_clear(&vstr_v_00_key_and_msg);
            vstr_clear(&vstr_v_01_key_and_msg);
            vstr_clear(&vstr_temp);
            return nonce;
        }

        vstr_t vstr_v_00;
        vstr_init(&vstr_v_00, vstr_v.len + 1);
        vstr_add_strn(&vstr_v_00, vstr_v.buf, vstr_v.len);
        vstr_add_byte(&vstr_v_00, 0x00);

        mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v_00.buf, vstr_v_00.len, (byte *)vstr_k.buf);

        mbedtls_md_hmac(mbedtls_md_info_from_type(self->algorithm->md_type), (const byte *)vstr_k.buf, vstr_k.len, (const byte *)vstr_v.buf, vstr_v.len, (byte *)vstr_v.buf);

        vstr_clear(&vstr_v_00);
        vstr_clear(&vstr_temp);
    }

    return mp_const_none;
}

static MP_DEFINE_CONST_FUN_OBJ_1(utils_rfc6979_gen_nonce_obj, utils_rfc6979_gen_nonce);

static const mp_rom_map_elem_t utils_rfc6979_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_gen_nonce), MP_ROM_PTR(&utils_rfc6979_gen_nonce_obj)},
};

static MP_DEFINE_CONST_DICT(utils_rfc6979_locals_dict, utils_rfc6979_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    utils_rfc6979_type,
    MP_QSTR_RFC6979,
    MP_TYPE_FLAG_NONE,
    locals_dict, &utils_rfc6979_locals_dict);

static mp_obj_t mod_rfc6979(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args)
{
    enum
    {
        ARG_msg,
        ARG_x,
        ARG_q,
        ARG_hashfunc
    };
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_msg, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_x, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_q, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
        {MP_QSTR_hashfunc, MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}},
    };

    mp_arg_val_t vals[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, vals);

    mp_obj_t msg = vals[ARG_msg].u_obj;
    mp_buffer_info_t bufinfo_msg;
    mp_get_buffer_raise(msg, &bufinfo_msg, MP_BUFFER_READ);

    mp_obj_t x = vals[ARG_x].u_obj;
    if (!mp_obj_is_int(x))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected x int"));
    }

    mp_obj_t q = vals[ARG_q].u_obj;
    if (!mp_obj_is_int(q))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected q int"));
    }

    mp_obj_t hash_algorithm = vals[ARG_hashfunc].u_obj;
    if (!mp_obj_is_type(hash_algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(hash_algorithm, &hash_algorithm_prehashed_type))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    mp_int_t qlen = mp_obj_get_int(int_bit_length(q));

    mp_util_rfc6979_t *RFC6979 = m_new_obj(mp_util_rfc6979_t);
    RFC6979->base.type = &utils_rfc6979_type;
    RFC6979->msg = msg;
    RFC6979->x = x;
    RFC6979->q = q;
    RFC6979->qlen = qlen;
    RFC6979->rlen = ((mp_int_t)(qlen + 7) / 8) * 8;
    RFC6979->algorithm = hash_algorithm;

    return MP_OBJ_FROM_PTR(RFC6979);
}

static MP_DEFINE_CONST_FUN_OBJ_KW(mod_rfc6979_obj, 3, mod_rfc6979);

static mp_obj_t rsa_deduce_private_exponent(mp_obj_t p, mp_obj_t q, mp_obj_t e)
{
    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_read_binary_from_mp_obj(&P, p, true);

    mbedtls_mpi Q;
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_read_binary_from_mp_obj(&Q, q, true);

    mbedtls_mpi E;
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary_from_mp_obj(&E, e, true);

    mbedtls_mpi D;
    mbedtls_mpi_init(&D);

    int ret = 1;
    if ((ret = mbedtls_rsa_deduce_private_exponent(&P, &Q, &E, &D)) != 0)
    {
        mbedtls_mpi_free(&P);
        mbedtls_mpi_free(&Q);
        mbedtls_mpi_free(&E);
        mbedtls_mpi_free(&D);
    }

    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&E);

    mp_obj_t d = mbedtls_mpi_write_binary_to_mp_obj(&D, true);
    mbedtls_mpi_free(&D);
    return d;
}

static MP_DEFINE_CONST_FUN_OBJ_3(mod_rsa_deduce_private_exponent_obj, rsa_deduce_private_exponent);

// ===== PyCA-compatible nested package layout (cryptography.hazmat.primitives...) =====
// Import resolution requires every intermediate level to be an mp_obj_module_t (see
// py/builtinimport.c process_import_at_level). Leaf packages are modules too so
// `import cryptography.hazmat.primitives.asymmetric.ec` works; their globals reference
// the existing class types + the PLAIN function objs (modules don't unwrap staticmethod).
// The flat top-level attributes (cryptography.ec ...) are kept unchanged (types).

static const mp_rom_map_elem_t crypto_pkg_hashes_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hashes)},
    {MP_ROM_QSTR(MP_QSTR_SHA1), MP_ROM_PTR(&hash_algorithm_sha1_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA256), MP_ROM_PTR(&hash_algorithm_sha256_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA384), MP_ROM_PTR(&hash_algorithm_sha384_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA512), MP_ROM_PTR(&hash_algorithm_sha512_type)},
    {MP_ROM_QSTR(MP_QSTR_BLAKE2s), MP_ROM_PTR(&hash_algorithm_blake2s_type)},
    {MP_ROM_QSTR(MP_QSTR_Hash), MP_ROM_PTR(&hash_context_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_hashes_globals, crypto_pkg_hashes_globals_table);
static const mp_obj_module_t crypto_pkg_hashes_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_hashes_globals,
};

static const mp_rom_map_elem_t crypto_pkg_hmac_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hmac)},
    {MP_ROM_QSTR(MP_QSTR_HMAC), MP_ROM_PTR(&hmac_context_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_hmac_globals, crypto_pkg_hmac_globals_table);
static const mp_obj_module_t crypto_pkg_hmac_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_hmac_globals,
};

static const mp_rom_map_elem_t crypto_pkg_serialization_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_serialization)},
    {MP_ROM_QSTR(MP_QSTR_load_der_public_key), MP_ROM_PTR(&mod_pk_parse_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_der_private_key), MP_ROM_PTR(&mod_pk_parse_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_pem_public_key), MP_ROM_PTR(&mod_pk_parse_public_key_pem_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_pem_private_key), MP_ROM_PTR(&mod_pk_parse_key_pem_obj)},
    {MP_ROM_QSTR(MP_QSTR_Encoding), MP_ROM_PTR(&encoding_type)},
    {MP_ROM_QSTR(MP_QSTR_PublicFormat), MP_ROM_PTR(&publicformat_type)},
    {MP_ROM_QSTR(MP_QSTR_PrivateFormat), MP_ROM_PTR(&privateformat_type)},
    {MP_ROM_QSTR(MP_QSTR_NoEncryption), MP_ROM_PTR(&mod_no_encryption_obj)},
    {MP_ROM_QSTR(MP_QSTR_BestAvailableEncryption), MP_ROM_PTR(&best_available_encryption_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_serialization_globals, crypto_pkg_serialization_globals_table);
static const mp_obj_module_t crypto_pkg_serialization_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_serialization_globals,
};

static const mp_rom_map_elem_t crypto_pkg_rsa_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_rsa)},
    {MP_ROM_QSTR(MP_QSTR_RSAPublicKey), MP_ROM_PTR(&rsa_public_key_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPublicNumbers), MP_ROM_PTR(&rsa_public_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPrivateKey), MP_ROM_PTR(&rsa_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPrivateNumbers), MP_ROM_PTR(&rsa_private_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_iqmp), MP_ROM_PTR(&mod_rsa_crt_iqmp_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_dmp1), MP_ROM_PTR(&mod_rsa_crt_dmp1_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_dmq1), MP_ROM_PTR(&mod_rsa_crt_dmq1_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_recover_prime_factors), MP_ROM_PTR(&mod_rsa_recover_prime_factors_obj)},
    {MP_ROM_QSTR(MP_QSTR_generate_private_key), MP_ROM_PTR(&mod_rsa_generate_private_key_obj)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_rsa_globals, crypto_pkg_rsa_globals_table);
static const mp_obj_module_t crypto_pkg_rsa_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_rsa_globals,
};

static const mp_rom_map_elem_t crypto_pkg_ec_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ec)},
    {MP_ROM_QSTR(MP_QSTR_ECDH), MP_ROM_PTR(&ec_ecdh_type)},
    {MP_ROM_QSTR(MP_QSTR_ECDSA), MP_ROM_PTR(&ec_ecdsa_type)},
    {MP_ROM_QSTR(MP_QSTR_SECP256R1), MP_ROM_PTR(&ec_curve_secp256r1_type)},
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    {MP_ROM_QSTR(MP_QSTR_SECP384R1), MP_ROM_PTR(&ec_curve_secp384r1_type)},
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    {MP_ROM_QSTR(MP_QSTR_SECP521R1), MP_ROM_PTR(&ec_curve_secp521r1_type)},
#endif
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePublicKey), MP_ROM_PTR(&ec_public_key_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePublicNumbers), MP_ROM_PTR(&ec_public_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePrivateKey), MP_ROM_PTR(&ec_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePrivateNumbers), MP_ROM_PTR(&ec_private_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_generate_private_key), MP_ROM_PTR(&mod_ec_generate_private_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_derive_private_key), MP_ROM_PTR(&mod_ec_derive_private_key_obj)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_ec_globals, crypto_pkg_ec_globals_table);
static const mp_obj_module_t crypto_pkg_ec_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_ec_globals,
};

static const mp_rom_map_elem_t crypto_pkg_ed25519_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ed25519)},
    {MP_ROM_QSTR(MP_QSTR_Ed25519PrivateKey), MP_ROM_PTR(&ed25519_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_Ed25519PublicKey), MP_ROM_PTR(&ed25519_public_key_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_ed25519_globals, crypto_pkg_ed25519_globals_table);
static const mp_obj_module_t crypto_pkg_ed25519_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_ed25519_globals,
};

static const mp_rom_map_elem_t crypto_pkg_padding_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_padding)},
    {MP_ROM_QSTR(MP_QSTR_PKCS1v15), MP_ROM_PTR(&mod_padding_pkcs1v15_obj)},
    {MP_ROM_QSTR(MP_QSTR_PSS), MP_ROM_PTR(&padding_pss_type)},
    {MP_ROM_QSTR(MP_QSTR_OAEP), MP_ROM_PTR(&padding_oaep_type)},
    {MP_ROM_QSTR(MP_QSTR_MGF1), MP_ROM_PTR(&mod_padding_mgf1_obj)},
    {MP_ROM_QSTR(MP_QSTR_calculate_max_pss_salt_length), MP_ROM_PTR(&mod_padding_calculate_max_pss_salt_length_obj)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_padding_globals, crypto_pkg_padding_globals_table);
static const mp_obj_module_t crypto_pkg_padding_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_padding_globals,
};

static const mp_rom_map_elem_t crypto_pkg_utils_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_utils)},
    {MP_ROM_QSTR(MP_QSTR_RFC6979), MP_ROM_PTR(&mod_rfc6979_obj)},
    {MP_ROM_QSTR(MP_QSTR_Prehashed), MP_ROM_PTR(&mod_hash_algorithm_prehashed_obj)},
    {MP_ROM_QSTR(MP_QSTR_constant_time_bytes_eq), MP_ROM_PTR(&mod_constant_time_bytes_eq_obj)},
    {MP_ROM_QSTR(MP_QSTR_bit_length), MP_ROM_PTR(&mod_int_bit_length_obj)},
    {MP_ROM_QSTR(MP_QSTR_encode_dss_signature), MP_ROM_PTR(&mod_encode_dss_signature_obj)},
    {MP_ROM_QSTR(MP_QSTR_decode_dss_signature), MP_ROM_PTR(&mod_decode_dss_signature_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_deduce_private_exponent), MP_ROM_PTR(&mod_rsa_deduce_private_exponent_obj)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_utils_globals, crypto_pkg_utils_globals_table);
static const mp_obj_module_t crypto_pkg_utils_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_utils_globals,
};

static const mp_rom_map_elem_t crypto_pkg_aead_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_aead)},
    {MP_ROM_QSTR(MP_QSTR_AESGCM), MP_ROM_PTR(&ciphers_aesgcm_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_aead_globals, crypto_pkg_aead_globals_table);
static const mp_obj_module_t crypto_pkg_aead_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_aead_globals,
};

static const mp_rom_map_elem_t crypto_pkg_ciphers_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ciphers)},
    {MP_ROM_QSTR(MP_QSTR_Cipher), MP_ROM_PTR(&ciphers_cipher_type)},
    {MP_ROM_QSTR(MP_QSTR_algorithms), MP_ROM_PTR(&ciphers_algorithms_type)},
    {MP_ROM_QSTR(MP_QSTR_modes), MP_ROM_PTR(&ciphers_modes_type)},
    {MP_ROM_QSTR(MP_QSTR_AESGCM), MP_ROM_PTR(&ciphers_aesgcm_type)},
    {MP_ROM_QSTR(MP_QSTR_aead), MP_ROM_PTR(&crypto_pkg_aead_module)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_ciphers_globals, crypto_pkg_ciphers_globals_table);
static const mp_obj_module_t crypto_pkg_ciphers_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_ciphers_globals,
};

static const mp_rom_map_elem_t crypto_pkg_asymmetric_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_asymmetric)},
    {MP_ROM_QSTR(MP_QSTR_rsa), MP_ROM_PTR(&crypto_pkg_rsa_module)},
    {MP_ROM_QSTR(MP_QSTR_ec), MP_ROM_PTR(&crypto_pkg_ec_module)},
    {MP_ROM_QSTR(MP_QSTR_ed25519), MP_ROM_PTR(&crypto_pkg_ed25519_module)},
    {MP_ROM_QSTR(MP_QSTR_padding), MP_ROM_PTR(&crypto_pkg_padding_module)},
    {MP_ROM_QSTR(MP_QSTR_utils), MP_ROM_PTR(&crypto_pkg_utils_module)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_asymmetric_globals, crypto_pkg_asymmetric_globals_table);
static const mp_obj_module_t crypto_pkg_asymmetric_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_asymmetric_globals,
};

static const mp_rom_map_elem_t crypto_pkg_hotp_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hotp)},
    {MP_ROM_QSTR(MP_QSTR_HOTP), MP_ROM_PTR(&twofactor_hotp_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_hotp_globals, crypto_pkg_hotp_globals_table);
static const mp_obj_module_t crypto_pkg_hotp_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_hotp_globals,
};

static const mp_rom_map_elem_t crypto_pkg_totp_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_totp)},
    {MP_ROM_QSTR(MP_QSTR_TOTP), MP_ROM_PTR(&twofactor_totp_type)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_totp_globals, crypto_pkg_totp_globals_table);
static const mp_obj_module_t crypto_pkg_totp_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_totp_globals,
};

static const mp_rom_map_elem_t crypto_pkg_twofactor_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_twofactor)},
    {MP_ROM_QSTR(MP_QSTR_HOTP), MP_ROM_PTR(&twofactor_hotp_type)},
    {MP_ROM_QSTR(MP_QSTR_TOTP), MP_ROM_PTR(&twofactor_totp_type)},
    {MP_ROM_QSTR(MP_QSTR_hotp), MP_ROM_PTR(&crypto_pkg_hotp_module)},
    {MP_ROM_QSTR(MP_QSTR_totp), MP_ROM_PTR(&crypto_pkg_totp_module)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_twofactor_globals, crypto_pkg_twofactor_globals_table);
static const mp_obj_module_t crypto_pkg_twofactor_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_twofactor_globals,
};

static const mp_rom_map_elem_t crypto_pkg_primitives_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_primitives)},
    {MP_ROM_QSTR(MP_QSTR_hashes), MP_ROM_PTR(&crypto_pkg_hashes_module)},
    {MP_ROM_QSTR(MP_QSTR_hmac), MP_ROM_PTR(&crypto_pkg_hmac_module)},
    {MP_ROM_QSTR(MP_QSTR_ciphers), MP_ROM_PTR(&crypto_pkg_ciphers_module)},
    {MP_ROM_QSTR(MP_QSTR_serialization), MP_ROM_PTR(&crypto_pkg_serialization_module)},
    {MP_ROM_QSTR(MP_QSTR_asymmetric), MP_ROM_PTR(&crypto_pkg_asymmetric_module)},
    {MP_ROM_QSTR(MP_QSTR_twofactor), MP_ROM_PTR(&crypto_pkg_twofactor_module)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_primitives_globals, crypto_pkg_primitives_globals_table);
static const mp_obj_module_t crypto_pkg_primitives_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_primitives_globals,
};

static const mp_rom_map_elem_t crypto_pkg_hazmat_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hazmat)},
    {MP_ROM_QSTR(MP_QSTR_primitives), MP_ROM_PTR(&crypto_pkg_primitives_module)},
};
static MP_DEFINE_CONST_DICT(crypto_pkg_hazmat_globals, crypto_pkg_hazmat_globals_table);
static const mp_obj_module_t crypto_pkg_hazmat_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_pkg_hazmat_globals,
};

static const mp_map_elem_t mp_module_ucryptography_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_cryptography)},
    {MP_ROM_QSTR(MP_QSTR_exceptions), MP_ROM_PTR((mp_obj_module_t *)&exceptions_module)},
    {MP_ROM_QSTR(MP_QSTR_x509), MP_ROM_PTR((mp_obj_module_t *)&x509_module)},
    {MP_ROM_QSTR(MP_QSTR_hazmat), MP_ROM_PTR((mp_obj_module_t *)&crypto_pkg_hazmat_module)},
};

static MP_DEFINE_CONST_DICT(mp_module_ucryptography_globals, mp_module_ucryptography_globals_table);

const mp_obj_module_t mp_module_ucryptography = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_ucryptography_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cryptography, mp_module_ucryptography);
