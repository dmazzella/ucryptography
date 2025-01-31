/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2024 Damiano Mazzella
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY of ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES of MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION of CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT of OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
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

    if (rng_state != NULL)
    {
        rng_state = NULL;
    }

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
#include "mbedtls/oid.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
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
} mp_x509_certificate_t;

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
static const mp_obj_type_t ed25519_type;
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
static const mp_obj_type_t ciphers_aesgcm_type;
static const mp_obj_type_t ciphers_cipher_type;
static const mp_obj_type_t ciphers_cipher_encryptor_type;
static const mp_obj_type_t ciphers_cipher_decryptor_type;
static const mp_obj_type_t ciphers_algorithms_aes_type;
static const mp_obj_type_t ciphers_algorithms_3des_type;
static const mp_obj_type_t ciphers_modes_cbc_type;
static const mp_obj_type_t ciphers_modes_gcm_type;
static const mp_obj_type_t ciphers_modes_ecb_type;
#if 0
static const mp_obj_type_t utils_rfc6979_type;
#endif
static const mp_obj_type_t padding_pkcs1v15_type;
static const mp_obj_type_t padding_pss_type;
static const mp_obj_type_t padding_oaep_type;
static const mp_obj_type_t padding_mgf1_type;
static const mp_obj_type_t twofactor_hotp_type;
static const mp_obj_type_t twofactor_totp_type;

#ifdef STM32WB
#ifdef MBEDTLS_GCM_ALT || MBEDTLS_AES_ALT
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

#if 0
#define DEBUG_MICROPYTHON_NEXTCHR "\n:"
static inline void micropython_printh(const uint8_t *b, size_t l)
{
    for (size_t i = 0; i < l; i++)
    {
        printf("%02X%c", b[i], DEBUG_MICROPYTHON_NEXTCHR[i < l - 1]);
    }
}

static vstr_t *vstr_hexlify(vstr_t *vstr_out, const byte *in, size_t in_len)
{
    vstr_init(vstr_out, in_len);

    if (in != NULL && in_len)
    {
        for (mp_uint_t i = in_len; i--;)
        {
            byte d = (*in >> 4);
            if (d > 9)
            {
                d += 'a' - '9' - 1;
            }
            vstr_add_char(vstr_out, d + '0');
            d = (*in++ & 0xf);
            if (d > 9)
            {
                d += 'a' - '9' - 1;
            }
            vstr_add_char(vstr_out, d + '0');
        }
    }

    return vstr_out;
}
#endif

#if 0
static void print_exception(vstr_t *vstr_print, mp_obj_t exc)
{
    mp_print_t print;
    vstr_clear(vstr_print);
    vstr_init_print(vstr_print, 16, &print);
    if (mp_obj_is_exception_instance(exc))
    {
        size_t n, *values;
        mp_obj_exception_get_traceback(exc, &n, &values);
        if (n > 0)
        {
            assert(n % 3 == 0);
            mp_print_str(&print, "Traceback (most recent call last):\n");
            for (int i = n - 3; i >= 0; i -= 3)
            {
#if MICROPY_ENABLE_SOURCE_LINE
                mp_printf(&print, "  File \"%q\", line %d", values[i], (int)values[i + 1]);
#else
                mp_printf(&print, "  File \"%q\"", values[i]);
#endif
                // the block name can be NULL if it's unknown
                qstr block = values[i + 2];
                if (block == MP_QSTR_NULL)
                {
                    mp_print_str(&print, "\n");
                }
                else
                {
                    mp_printf(&print, ", in %q\n", block);
                }
            }
        }
    }
    mp_obj_print_helper(&print, exc, PRINT_EXC);
    mp_print_str(&print, "\n");
}
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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_int_bit_length_obj, MP_ROM_PTR(&mod_int_bit_length_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_constant_time_bytes_eq_obj, MP_ROM_PTR(&mod_constant_time_bytes_eq_obj));

static int util_decode_dss_signature(const unsigned char *sig, size_t slen, mbedtls_mpi *r, mbedtls_mpi *s)
{
    int ret;
    unsigned char *p = (unsigned char *)sig;
    const unsigned char *end = sig + slen;
    size_t len;
    if(sig == NULL) {
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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_decode_dss_signature_obj, MP_ROM_PTR(&mod_decode_dss_signature_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_encode_dss_signature_obj, MP_ROM_PTR(&mod_encode_dss_signature_obj));

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
    mp_obj_int_to_bytes_impl(s2b_x, true, x_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len));
    mp_obj_int_to_bytes_impl(s2b_y, true, y_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len) + (n_size - y_len) + x_len);

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
    mp_obj_int_to_bytes_impl(s2b_x, true, x_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len));
    mp_obj_int_to_bytes_impl(s2b_y, true, y_len, (byte *)vstr_public_bytes.buf + 1 + (n_size - x_len) + (n_size - y_len) + x_len);

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
    mp_obj_int_to_bytes_impl(cryptography_small_to_big_int(private_value), true, pksize, (byte *)vstr_private_bytes.buf);

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
    if (!mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(ecdsa->algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm"));
    }

    vstr_t vstr_digest;
    if ((mp_obj_get_type(ecdsa->algorithm) == &mp_type_NoneType))
    {
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else if (mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_prehashed_type))
    {
        mp_hash_algorithm_t *HashAlgorithm = (mp_hash_algorithm_t *)((mp_util_prehashed_t *)MP_OBJ_TO_PTR(ecdsa->algorithm))->algorithm;
        (void)HashAlgorithm;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else
    {
        mp_hash_algorithm_t *HashAlgorithm = MP_OBJ_TO_PTR(ecdsa->algorithm);
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(HashAlgorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(HashAlgorithm->md_type), (const byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_digest.buf);
    }

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
    if (!mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(ecdsa->algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm or None"));
    }

    vstr_t vstr_digest;
    if ((mp_obj_get_type(ecdsa->algorithm) == &mp_type_NoneType))
    {
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else if (mp_obj_is_type(ecdsa->algorithm, &hash_algorithm_prehashed_type))
    {
        mp_hash_algorithm_t *HashAlgorithm = (mp_hash_algorithm_t *)((mp_util_prehashed_t *)MP_OBJ_TO_PTR(ecdsa->algorithm))->algorithm;
        (void)HashAlgorithm;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else
    {
        mp_hash_algorithm_t *HashAlgorithm = MP_OBJ_TO_PTR(ecdsa->algorithm);
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(HashAlgorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(HashAlgorithm->md_type), (const byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_digest.buf);
    }

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
    int ecdsa_sign = 1;
    if ((ecdsa_sign = mbedtls_ecdsa_sign(&ecp.private_grp, &r, &s, &ecp.private_d, (const byte *)vstr_digest.buf, vstr_digest.len, mp_random, NULL) != 0))
    {
        mbedtls_ecp_keypair_free(&ecp);
        vstr_clear(&vstr_digest);
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
    (void)encryption_algorithm;

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_hash_algorithm_prehashed_obj, MP_ROM_PTR(&mod_hash_algorithm_prehashed_obj));

static mp_obj_t hash_algorithm_sha1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha1_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA1;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
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
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha256_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA256;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
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
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha384_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA384;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
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
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_sha512_type;
    HashAlgorithm->md_type = MBEDTLS_MD_SHA512;
    return MP_OBJ_FROM_PTR(HashAlgorithm);
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

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(self->data, &bufinfo_data, MP_BUFFER_READ);

    mp_hash_context_t *HashContext = m_new_obj(mp_hash_context_t);
    HashContext->base.type = &hash_context_type;
    HashContext->data = vstr_new(bufinfo_data.len);
    vstr_add_strn(self->data, bufinfo_data.buf, bufinfo_data.len);
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

static const mp_rom_map_elem_t hashes_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_SHA1), MP_ROM_PTR(&hash_algorithm_sha1_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA256), MP_ROM_PTR(&hash_algorithm_sha256_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA384), MP_ROM_PTR(&hash_algorithm_sha384_type)},
    {MP_ROM_QSTR(MP_QSTR_SHA512), MP_ROM_PTR(&hash_algorithm_sha512_type)},
    {MP_ROM_QSTR(MP_QSTR_BLAKE2s), MP_ROM_PTR(&hash_algorithm_blake2s_type)},
    {MP_ROM_QSTR(MP_QSTR_Hash), MP_ROM_PTR(&hash_context_type)},
};

static MP_DEFINE_CONST_DICT(hashes_locals_dict, hashes_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hashes_type,
    MP_QSTR_hashes,
    MP_TYPE_FLAG_NONE,
    locals_dict, &hashes_locals_dict);

static mp_obj_t hmac_context_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
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

    mp_hmac_context_t *HMACContext = m_new_obj(mp_hmac_context_t);
    HMACContext->base.type = &hmac_context_type;
    HMACContext->key = vstr_new(self->key->len);
    vstr_add_strn(HMACContext->data, self->key->buf, self->key->len);
    HMACContext->data = vstr_new(self->data->len);
    vstr_add_strn(HMACContext->data, self->data->buf, self->data->len);
    HMACContext->finalized = false;

    return MP_OBJ_FROM_PTR(HMACContext);
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_hmac_algorithm_copy_obj, hmac_algorithm_copy);

static mp_obj_t hmac_algorithm_verify(mp_obj_t obj, mp_obj_t data)
{
    mp_hmac_context_t *self = MP_OBJ_TO_PTR(obj);
    if (self->finalized)
    {
        mp_raise_msg(&mp_type_AlreadyFinalized, NULL);
    }

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(data, &bufinfo_data, MP_BUFFER_READ);

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

static const mp_rom_map_elem_t hmac_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_HMAC), MP_ROM_PTR(&hmac_context_type)},
};

static MP_DEFINE_CONST_DICT(hmac_locals_dict, hmac_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    hmac_type,
    MP_QSTR_hmac,
    MP_TYPE_FLAG_NONE,
    locals_dict, &hmac_locals_dict);

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
    if (n_args == 1)
    {
        return self->public_bytes;
    }
    else if (n_args == 2)
    {
        if (self->ec_public_key != NULL)
        {
            return ec_key_dumps(self->public_bytes, mp_const_none, args[1], self->ec_public_key->public_numbers->curve->ecp_group_id);
        }
        else if (self->rsa_public_key != NULL)
        {
            return rsa_key_dumps(self->rsa_public_key->public_numbers, MP_OBJ_NULL, args[1]);
        }
    }
    return mp_const_none;
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
            if (attr == MP_QSTR_not_valid_before)
            {
                dest[0] = self->not_valid_before;
                return;
            }
            if (attr == MP_QSTR_not_valid_after)
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

static mp_obj_t x509_crt_parse_oid(const mbedtls_asn1_buf *o, const mp_obj_type_t *type)
{
    vstr_t vstr_oid;
    vstr_init(&vstr_oid, 0);
    unsigned int value = 0;

    for (size_t i = 0; i < o->len; i++)
    {
        if (i == 0)
        {
            vstr_printf(&vstr_oid, "%d.%d", o->p[0] / 40, o->p[0] % 40);
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

static mp_obj_t x509_crt_parse_name(const mbedtls_x509_name *dn)
{
    mp_obj_t rdn_dict = mp_obj_new_dict(0);
    const char *short_name = NULL;
    const mbedtls_x509_name *name = dn;
    while (name != NULL)
    {
        if (!name->oid.p)
        {
            name = name->next;
            continue;
        }

        mbedtls_oid_get_attr_short_name(&name->oid, &short_name);
        if (short_name != NULL)
        {
            mp_obj_dict_store(rdn_dict, mp_obj_new_str_via_qstr(short_name, strlen(short_name)), mp_obj_new_bytes(name->val.p, name->val.len));
        }
        else
        {
            mp_obj_dict_store(rdn_dict, x509_crt_parse_oid(&name->oid, &mp_type_str), mp_obj_new_bytes(name->val.p, name->val.len));
        }

        name = name->next;
    }
    return rdn_dict;
}

static mp_obj_t x509_crt_parse_ext_key_usage(const mbedtls_x509_sequence *extended_key_usage)
{
    const mbedtls_x509_sequence *cur = extended_key_usage;
    const char *desc = NULL;
    mp_obj_t ext_key_usage = mp_obj_new_dict(0);

    while (cur != NULL)
    {
        if (mbedtls_oid_get_extended_key_usage(&cur->buf, &desc) == 0)
        {
            mp_obj_dict_store(ext_key_usage, x509_crt_parse_oid(&cur->buf, &mp_type_str), mp_obj_new_bytes((const byte *)desc, strlen(desc)));
        }
        cur = cur->next;
    }

    return ext_key_usage;
}

static mp_obj_t x509_crt_parse_key_usage(const unsigned int ku)
{
    mp_obj_t key_usage = mp_obj_new_dict(0);
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_signature), mp_obj_new_bool(ku & MBEDTLS_X509_KU_DIGITAL_SIGNATURE));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_non_repudiation), mp_obj_new_bool(ku & MBEDTLS_X509_KU_NON_REPUDIATION));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_key_encipherment), mp_obj_new_bool(ku & MBEDTLS_X509_KU_KEY_ENCIPHERMENT));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_data_encipherment), mp_obj_new_bool(ku & MBEDTLS_X509_KU_DATA_ENCIPHERMENT));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_key_agreement), mp_obj_new_bool(ku & MBEDTLS_X509_KU_KEY_AGREEMENT));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_key_cert_sign), mp_obj_new_bool(ku & MBEDTLS_X509_KU_KEY_CERT_SIGN));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_crl_sign), mp_obj_new_bool(ku & MBEDTLS_X509_KU_CRL_SIGN));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_encipher_only), mp_obj_new_bool(ku & MBEDTLS_X509_KU_ENCIPHER_ONLY));
    mp_obj_dict_store(key_usage, MP_ROM_QSTR(MP_QSTR_digital_decipher_only), mp_obj_new_bool(ku & MBEDTLS_X509_KU_DECIPHER_ONLY));
    return key_usage;
}

static void x509_crt_dump(const mbedtls_x509_crt *crt)
{
    vstr_t vstr_crt;
    vstr_init_len(&vstr_crt, crt->raw.len);
    mbedtls_x509_crt_info(vstr_crt.buf, vstr_crt.len, "", crt);
    printf("certificate info: %s\n", vstr_crt.buf);
    vstr_clear(&vstr_crt);
}

static mp_obj_t x509_crt_parse_der(mp_obj_t certificate)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(certificate, &bufinfo, MP_BUFFER_READ);

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der_nocopy(&crt, (const byte *)bufinfo.buf, bufinfo.len) != 0)
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

    mp_obj_t extensions = mp_obj_new_dict(0);
    mp_obj_dict_store(extensions, MP_ROM_QSTR(MP_QSTR_extended_key_usage), x509_crt_parse_ext_key_usage(&crt.ext_key_usage));
    mp_obj_dict_store(extensions, MP_ROM_QSTR(MP_QSTR_key_usage), x509_crt_parse_key_usage(crt.private_key_usage));

    const char *signature_algorithm_oid_desc = NULL;
    mbedtls_oid_get_sig_alg_desc(&crt.sig_oid, &signature_algorithm_oid_desc);
    mp_obj_t signature_algorithm_oid = mp_obj_new_dict(0);
    mp_obj_dict_store(signature_algorithm_oid, x509_crt_parse_oid(&crt.sig_oid, &mp_type_str), mp_obj_new_str(signature_algorithm_oid_desc, strlen(signature_algorithm_oid_desc)));

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

static MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_crt_parse_der_obj, x509_crt_parse_der);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_x509_crt_parse_der_obj, MP_ROM_PTR(&mod_x509_crt_parse_der_obj));

static const mp_rom_map_elem_t x509_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_load_der_x509_certificate), MP_ROM_PTR(&mod_static_x509_crt_parse_der_obj)},
    {MP_ROM_QSTR(MP_QSTR_Certificate), MP_ROM_PTR(&x509_certificate_type)},
};

static MP_DEFINE_CONST_DICT(x509_locals_dict, x509_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    x509_type,
    MP_QSTR_x509,
    MP_TYPE_FLAG_NONE,
    locals_dict, &x509_locals_dict);

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_pk_parse_public_key_obj, MP_ROM_PTR(&mod_pk_parse_public_key_obj));

static mp_obj_t pk_parse_key(mp_obj_t private_key, mp_obj_t password)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(private_key, &bufinfo, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo1;
    bool use_password = mp_get_buffer(password, &bufinfo1, MP_BUFFER_READ);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_key(&pk, (const byte *)bufinfo.buf, bufinfo.len, (use_password ? (const byte *)bufinfo1.buf : NULL), bufinfo1.len, mp_random, NULL) != 0)
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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_pk_parse_key_obj, MP_ROM_PTR(&mod_pk_parse_key_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_no_encryption_obj, MP_ROM_PTR(&mod_no_encryption_obj));

static const mp_rom_map_elem_t serialization_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_load_der_public_key), MP_ROM_PTR(&mod_static_pk_parse_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_der_private_key), MP_ROM_PTR(&mod_static_pk_parse_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_Encoding), MP_ROM_PTR(&encoding_type)},
    {MP_ROM_QSTR(MP_QSTR_PublicFormat), MP_ROM_PTR(&publicformat_type)},
    {MP_ROM_QSTR(MP_QSTR_PrivateFormat), MP_ROM_PTR(&privateformat_type)},
    {MP_ROM_QSTR(MP_QSTR_NoEncryption), MP_ROM_PTR(&mod_static_no_encryption_obj)},
};

static MP_DEFINE_CONST_DICT(serialization_locals_dict, serialization_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    serialization_type,
    MP_QSTR_serialization,
    MP_TYPE_FLAG_NONE,
    locals_dict, &serialization_locals_dict);

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
        return mp_const_none;
    }

    mp_obj_t priv_key = ec_parse_keypair(&ecp, true);
    mbedtls_ecp_keypair_free(&ecp);
    return priv_key;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_generate_private_key_obj, ec_generate_private_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ec_generate_private_key_obj, MP_ROM_PTR(&mod_ec_generate_private_key_obj));

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
    mp_obj_int_to_bytes_impl(cryptography_small_to_big_int(private_value), true, pksize, (byte *)vstr_private_bytes.buf);

    if (mbedtls_ecp_read_key(ecp.private_grp.id, &ecp, (const byte *)vstr_private_bytes.buf, vstr_private_bytes.len) != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        vstr_clear(&vstr_private_bytes);
        return mp_const_none;
    }
    if (mbedtls_ecp_mul(&ecp.private_grp, &ecp.private_Q, &ecp.private_d, &ecp.private_grp.G, mp_random, NULL) != 0)
    {
        mbedtls_ecp_keypair_free(&ecp);
        vstr_clear(&vstr_private_bytes);
        return mp_const_none;
    }
    mp_obj_t priv_key = ec_parse_keypair(&ecp, true);
    mbedtls_ecp_keypair_free(&ecp);
    vstr_clear(&vstr_private_bytes);
    return priv_key;
}

static MP_DEFINE_CONST_FUN_OBJ_2(mod_ec_derive_private_key_obj, ec_derive_private_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_ec_derive_private_key_obj, MP_ROM_PTR(&mod_ec_derive_private_key_obj));

static const mp_rom_map_elem_t ec_locals_dict_table[] = {
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
    {MP_ROM_QSTR(MP_QSTR_generate_private_key), MP_ROM_PTR(&mod_static_ec_generate_private_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_derive_private_key), MP_ROM_PTR(&mod_static_ec_derive_private_key_obj)},
};

static MP_DEFINE_CONST_DICT(ec_locals_dict, ec_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ec_type,
    MP_QSTR_ec,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ec_locals_dict);

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_padding_calculate_max_pss_salt_length_obj, MP_ROM_PTR(&mod_padding_calculate_max_pss_salt_length_obj));

static mp_obj_t padding_pss_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args)
{
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

#if 0
    if (!mp_obj_is_type(label, &mp_type_bytes) && !mp_obj_is_type(label, &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of bytes or None"));
    }
#endif

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

static const mp_rom_map_elem_t padding_mgf1_locals_dict_table[] = {

};

static MP_DEFINE_CONST_DICT(padding_mgf1_locals_dict, padding_mgf1_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_mgf1_type,
    MP_QSTR_MGF1,
    MP_TYPE_FLAG_NONE,
    locals_dict, &padding_mgf1_locals_dict);

static mp_obj_t padding_pkcs1v15(void)
{
    mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = m_new_obj(mp_padding_pkcs1v15_t);
    PADDING_PKCS1V15->base.type = &padding_pkcs1v15_type;
    PADDING_PKCS1V15->name = mp_obj_new_str("EMSA-PKCS1-v1_5", strlen("EMSA-PKCS1-v1_5"));

    return MP_OBJ_FROM_PTR(PADDING_PKCS1V15);
}

static MP_DEFINE_CONST_FUN_OBJ_0(mod_padding_pkcs1v15_obj, padding_pkcs1v15);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_padding_pkcs1v15_obj, MP_ROM_PTR(&mod_padding_pkcs1v15_obj));

static mp_obj_t padding_mgf1(mp_obj_t algorithm)
{
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
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_padding_mgf1_obj, padding_mgf1);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_padding_mgf1_obj, MP_ROM_PTR(&mod_padding_mgf1_obj));

static const mp_rom_map_elem_t padding_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_PKCS1v15), MP_ROM_PTR(&mod_static_padding_pkcs1v15_obj)},
    {MP_ROM_QSTR(MP_QSTR_PSS), MP_ROM_PTR(&padding_pss_type)},
    {MP_ROM_QSTR(MP_QSTR_OAEP), MP_ROM_PTR(&padding_oaep_type)},
    {MP_ROM_QSTR(MP_QSTR_MGF1), MP_ROM_PTR(&mod_static_padding_mgf1_obj)},
    {MP_ROM_QSTR(MP_QSTR_calculate_max_pss_salt_length), MP_ROM_PTR(&mod_static_padding_calculate_max_pss_salt_length_obj)},
};

static MP_DEFINE_CONST_DICT(padding_locals_dict, padding_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    padding_type,
    MP_QSTR_padding,
    MP_TYPE_FLAG_NONE,
    locals_dict, &padding_locals_dict);

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
    if (!mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm or None"));
    }

    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType) && mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PKCS1v15 for hashes algorithm None"));
    }

    vstr_t vstr_digest;
    mp_hash_algorithm_t *HashAlgorithm = NULL;
    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType))
    {
        HashAlgorithm = NULL;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else if (mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        HashAlgorithm = (mp_hash_algorithm_t *)((mp_util_prehashed_t *)MP_OBJ_TO_PTR(algorithm))->algorithm;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else
    {
        HashAlgorithm = MP_OBJ_TO_PTR(algorithm);
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(HashAlgorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(HashAlgorithm->md_type), (const byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_digest.buf);
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
#if 0
        if (PADDING_PSS->salt_length == 0)
        {
            salt_length = mp_obj_get_int(padding_calculate_max_pss_salt_length(args[0], PADDING_PSS->mgf->algorithm));
        }
#endif
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_PSS->mgf->algorithm->md_type);
    }
    else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
    {
#if 0
        mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = MP_OBJ_TO_PTR(padding);
#endif
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
#if 0
        mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = MP_OBJ_TO_PTR(padding);
#endif
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
        }

        byte buf[MBEDTLS_MPI_MAX_SIZE];
        memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
        size_t olen = 0;
        ret = mbedtls_pk_encrypt(&pk, (const byte *)bufinfo_plaintext.buf, bufinfo_plaintext.len, buf, &olen, sizeof(buf), mp_random, NULL);
        enc = mp_obj_new_bytes((const byte *)buf, olen);
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

    mbedtls_mpi DMP1;
    mbedtls_mpi_init(&DMP1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMP1, RSAPrivateNumbers->dmp1, true);
    mbedtls_mpi_free(&DMP1);

    mbedtls_mpi DMQ1;
    mbedtls_mpi_init(&DMQ1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMQ1, RSAPrivateNumbers->dmq1, true);
    mbedtls_mpi_free(&DMQ1);

    mbedtls_mpi IQMP;
    mbedtls_mpi_init(&IQMP);
    mbedtls_mpi_read_binary_from_mp_obj(&IQMP, RSAPrivateNumbers->iqmp, true);
    mbedtls_mpi_free(&IQMP);

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
#if 0
                mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = MP_OBJ_TO_PTR(padding);
#endif
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
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_rsa_import"));
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
    if (!mp_obj_is_type(algorithm, &hash_algorithm_sha1_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha256_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha384_type) && !mp_obj_is_type(algorithm, &hash_algorithm_sha512_type) && !mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type) && !(mp_obj_get_type(algorithm) == &mp_type_NoneType))
    {
        mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("Expected instance of hashes algorithm or None"));
    }

    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType) && mp_obj_is_type(padding, &padding_pss_type))
    {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Expected instance of padding.PKCS1v15 for hashes algorithm None"));
    }

    vstr_t vstr_digest;
    mp_hash_algorithm_t *HashAlgorithm = NULL;
    if ((mp_obj_get_type(algorithm) == &mp_type_NoneType))
    {
        HashAlgorithm = NULL;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else if (mp_obj_is_type(algorithm, &hash_algorithm_prehashed_type))
    {
        HashAlgorithm = (mp_hash_algorithm_t *)((mp_util_prehashed_t *)MP_OBJ_TO_PTR(algorithm))->algorithm;
        vstr_init_len(&vstr_digest, 0);
        vstr_add_strn(&vstr_digest, (const char *)bufinfo_data.buf, bufinfo_data.len);
    }
    else
    {
        HashAlgorithm = MP_OBJ_TO_PTR(algorithm);
        vstr_init_len(&vstr_digest, mbedtls_md_get_size(mbedtls_md_info_from_type(HashAlgorithm->md_type)));
        mbedtls_md(mbedtls_md_info_from_type(HashAlgorithm->md_type), (const byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_digest.buf);
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

    mbedtls_mpi DMP1;
    mbedtls_mpi_init(&DMP1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMP1, RSAPrivateNumbers->dmp1, true);
    mbedtls_mpi_free(&DMP1);

    mbedtls_mpi DMQ1;
    mbedtls_mpi_init(&DMQ1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMQ1, RSAPrivateNumbers->dmq1, true);
    mbedtls_mpi_free(&DMQ1);

    mbedtls_mpi IQMP;
    mbedtls_mpi_init(&IQMP);
    mbedtls_mpi_read_binary_from_mp_obj(&IQMP, RSAPrivateNumbers->iqmp, true);
    mbedtls_mpi_free(&IQMP);

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
#if 0
                if (PADDING_PSS->salt_length == 0)
                {
                    salt_length = mp_obj_get_int(padding_calculate_max_pss_salt_length(args[0], PADDING_PSS->mgf->algorithm));
                }
#endif
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, PADDING_PSS->mgf->algorithm->md_type);
            }
            else if (mp_obj_is_type(padding, &padding_pkcs1v15_type))
            {
#if 0
                mp_padding_pkcs1v15_t *PADDING_PKCS1V15 = MP_OBJ_TO_PTR(padding);
#endif
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
    (void)encryption_algorithm;

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

    mbedtls_mpi DMP1;
    mbedtls_mpi_init(&DMP1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMP1, dmp1, true);
    mbedtls_mpi_free(&DMP1);

    mbedtls_mpi DMQ1;
    mbedtls_mpi_init(&DMQ1);
    mbedtls_mpi_read_binary_from_mp_obj(&DMQ1, dmq1, true);
    mbedtls_mpi_free(&DMQ1);

    mbedtls_mpi IQMP;
    mbedtls_mpi_init(&IQMP);
    mbedtls_mpi_read_binary_from_mp_obj(&IQMP, iqmp, true);
    mbedtls_mpi_free(&IQMP);

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
    mbedtls_mpi_free(&DMP1);
    mbedtls_mpi_free(&DMQ1);
    mbedtls_mpi_free(&IQMP);
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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_crt_iqmp_obj, MP_ROM_PTR(&mod_rsa_crt_iqmp_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_crt_dmp1_obj, MP_ROM_PTR(&mod_rsa_crt_dmp1_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_crt_dmq1_obj, MP_ROM_PTR(&mod_rsa_crt_dmq1_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_recover_prime_factors_obj, MP_ROM_PTR(&mod_rsa_recover_prime_factors_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_generate_private_key_obj, MP_ROM_PTR(&mod_rsa_generate_private_key_obj));

static const mp_rom_map_elem_t rsa_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_RSAPublicKey), MP_ROM_PTR(&rsa_public_key_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPublicNumbers), MP_ROM_PTR(&rsa_public_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPrivateKey), MP_ROM_PTR(&rsa_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_RSAPrivateNumbers), MP_ROM_PTR(&rsa_private_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_iqmp), MP_ROM_PTR(&mod_static_rsa_crt_iqmp_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_dmp1), MP_ROM_PTR(&mod_static_rsa_crt_dmp1_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_crt_dmq1), MP_ROM_PTR(&mod_static_rsa_crt_dmq1_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_recover_prime_factors), MP_ROM_PTR(&mod_static_rsa_recover_prime_factors_obj)},
    {MP_ROM_QSTR(MP_QSTR_generate_private_key), MP_ROM_PTR(&mod_static_rsa_generate_private_key_obj)},
};

static MP_DEFINE_CONST_DICT(rsa_locals_dict, rsa_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    rsa_type,
    MP_QSTR_rsa,
    MP_TYPE_FLAG_NONE,
    locals_dict, &rsa_locals_dict);

static mp_obj_t ed25519_private_key_from_private_bytes(mp_obj_t data)
{
#if !defined(MICROPY_PY_UCRYPTOGRAPHY_ED25519)
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("ed25519 is not supported"));
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
#if !defined(MICROPY_PY_UCRYPTOGRAPHY_ED25519)
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("ed25519 is not supported"));
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
#if !defined(MICROPY_PY_UCRYPTOGRAPHY_ED25519)
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("ed25519 is not supported"));
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
#if !defined(MICROPY_PY_UCRYPTOGRAPHY_ED25519)
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("ed25519 is not supported"));
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
#if !defined(MICROPY_PY_UCRYPTOGRAPHY_ED25519)
    mp_raise_msg(&mp_type_UnsupportedAlgorithm, MP_ERROR_TEXT("ed25519 is not supported"));
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

static const mp_rom_map_elem_t ed25519_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_Ed25519PrivateKey), MP_ROM_PTR(&ed25519_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_Ed25519PublicKey), MP_ROM_PTR(&ed25519_public_key_type)},
};

static MP_DEFINE_CONST_DICT(ed25519_locals_dict, ed25519_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ed25519_type,
    MP_QSTR_ed25519,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ed25519_locals_dict);

static const mp_rom_map_elem_t exceptions_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_InvalidSignature), MP_ROM_PTR(&mp_type_InvalidSignature)},
    {MP_ROM_QSTR(MP_QSTR_AlreadyFinalized), MP_ROM_PTR(&mp_type_AlreadyFinalized)},
    {MP_ROM_QSTR(MP_QSTR_UnsupportedAlgorithm), MP_ROM_PTR(&mp_type_UnsupportedAlgorithm)},
    {MP_ROM_QSTR(MP_QSTR_InvalidKey), MP_ROM_PTR(&mp_type_InvalidKey)},
    {MP_ROM_QSTR(MP_QSTR_InvalidToken), MP_ROM_PTR(&mp_type_InvalidToken)},
};

static MP_DEFINE_CONST_DICT(exceptions_locals_dict, exceptions_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    exceptions_type,
    MP_QSTR_exceptions,
    MP_TYPE_FLAG_NONE,
    locals_dict, &exceptions_locals_dict);

static mp_obj_t aesgcm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_obj_t key = args[0];

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(key, &bufinfo_key, MP_BUFFER_READ);

    mp_ciphers_aesgcm_t *AESGCM = m_new_obj(mp_ciphers_aesgcm_t);
    AESGCM->base.type = &ciphers_aesgcm_type;
    AESGCM->key = vstr_new(bufinfo_key.len);
    vstr_add_strn(AESGCM->key, bufinfo_key.buf, bufinfo_key.len);

    return MP_OBJ_FROM_PTR(AESGCM);
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

    vstr_t vstr_tag;
    vstr_init_len(&vstr_tag, 16);

    vstr_t vstr_output;
    vstr_init_len(&vstr_output, bufinfo_data.len - vstr_tag.len);
    size_t olen = 0;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (byte *)AESGCM->key->buf, (AESGCM->key->len * 8));
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, bufinfo_nonce.buf, bufinfo_nonce.len);
    mbedtls_gcm_update_ad(&ctx, (use_associated_data ? bufinfo_associated_data.buf : NULL), (use_associated_data ? bufinfo_associated_data.len : 0));
    mbedtls_gcm_update(&ctx, bufinfo_data.buf, bufinfo_data.len, (byte *)vstr_output.buf, vstr_output.len, &olen);
    mbedtls_gcm_finish(&ctx, (byte *)vstr_output.buf, vstr_output.len, &olen, (byte *)vstr_tag.buf, vstr_tag.len);
    mbedtls_gcm_free(&ctx);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf, vstr_output.len);
    vstr_clear(&vstr_tag);
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
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_algorithms_aes_type,
    MP_QSTR_AES,
    MP_TYPE_FLAG_NONE,
    make_new, algorithms_aes_make_new);

#ifdef MBEDTLS_DES_C
static mp_obj_t algorithms_3des_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
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
}

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_algorithms_3des_type,
    MP_QSTR_TripleDES,
    MP_TYPE_FLAG_NONE,
    make_new, algorithms_3des_make_new);
#endif

static const mp_rom_map_elem_t ciphers_algorithms_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_AES), MP_ROM_PTR(&ciphers_algorithms_aes_type)},
#ifdef MBEDTLS_DES_C
    {MP_ROM_QSTR(MP_QSTR_TripleDES), MP_ROM_PTR(&ciphers_algorithms_3des_type)},
#endif

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
        vstr_add_strn(GCM->tag, bufinfo_tag.buf, bufinfo_tag.len);
    }
    else
    {
        GCM->tag->len = GCM->min_tag_length;
    }

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

static const mp_rom_map_elem_t ciphers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_AESGCM), MP_ROM_PTR(&ciphers_aesgcm_type)},
    {MP_ROM_QSTR(MP_QSTR_Cipher), MP_ROM_PTR(&ciphers_cipher_type)},
    {MP_ROM_QSTR(MP_QSTR_algorithms), MP_ROM_PTR(&ciphers_algorithms_type)},
    {MP_ROM_QSTR(MP_QSTR_modes), MP_ROM_PTR(&ciphers_modes_type)},
};

static MP_DEFINE_CONST_DICT(ciphers_locals_dict, ciphers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_type,
    MP_QSTR_ciphers,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ciphers_locals_dict);

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
    mp_obj_int_to_bytes_impl(counter, true, vstr_counter.len, (byte *)vstr_counter.buf);

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

    if (!mp_obj_equal(hotp_value, hotp))
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

    if (!mp_obj_equal(hotp_value, totp))
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

static const mp_rom_map_elem_t twofactor_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_HOTP), MP_ROM_PTR(&twofactor_hotp_type)},
    {MP_ROM_QSTR(MP_QSTR_TOTP), MP_ROM_PTR(&twofactor_totp_type)},
};

static MP_DEFINE_CONST_DICT(twofactor_locals_dict, twofactor_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    twofactor_type,
    MP_QSTR_twofactor,
    MP_TYPE_FLAG_NONE,
    locals_dict, &twofactor_locals_dict);

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rfc6979_obj, MP_ROM_PTR(&mod_rfc6979_obj));

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
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_rsa_deduce_private_exponent_obj, MP_ROM_PTR(&mod_rsa_deduce_private_exponent_obj));

static const mp_rom_map_elem_t utils_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_RFC6979), MP_ROM_PTR(&mod_static_rfc6979_obj)},
    {MP_ROM_QSTR(MP_QSTR_Prehashed), MP_ROM_PTR(&mod_static_hash_algorithm_prehashed_obj)},
    {MP_ROM_QSTR(MP_QSTR_constant_time_bytes_eq), MP_ROM_PTR(&mod_static_constant_time_bytes_eq_obj)},
    {MP_ROM_QSTR(MP_QSTR_bit_length), MP_ROM_PTR(&mod_static_int_bit_length_obj)},
    {MP_ROM_QSTR(MP_QSTR_encode_dss_signature), MP_ROM_PTR(&mod_static_encode_dss_signature_obj)},
    {MP_ROM_QSTR(MP_QSTR_decode_dss_signature), MP_ROM_PTR(&mod_static_decode_dss_signature_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_deduce_private_exponent), MP_ROM_PTR(&mod_static_rsa_deduce_private_exponent_obj)},
};

static MP_DEFINE_CONST_DICT(utils_locals_dict, utils_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    utils_type,
    MP_QSTR_utils,
    MP_TYPE_FLAG_NONE,
    locals_dict, &utils_locals_dict);

static const mp_map_elem_t mp_module_ucryptography_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_cryptography)},
    {MP_ROM_QSTR(MP_QSTR_ciphers), MP_ROM_PTR((mp_obj_type_t *)&ciphers_type)},
    {MP_ROM_QSTR(MP_QSTR_ec), MP_ROM_PTR((mp_obj_type_t *)&ec_type)},
    {MP_ROM_QSTR(MP_QSTR_ed25519), MP_ROM_PTR((mp_obj_type_t *)&ed25519_type)},
    {MP_ROM_QSTR(MP_QSTR_exceptions), MP_ROM_PTR((mp_obj_type_t *)&exceptions_type)},
    {MP_ROM_QSTR(MP_QSTR_hashes), MP_ROM_PTR((mp_obj_type_t *)&hashes_type)},
    {MP_ROM_QSTR(MP_QSTR_hmac), MP_ROM_PTR((mp_obj_type_t *)&hmac_type)},
    {MP_ROM_QSTR(MP_QSTR_padding), MP_ROM_PTR((mp_obj_type_t *)&padding_type)},
    {MP_ROM_QSTR(MP_QSTR_rsa), MP_ROM_PTR((mp_obj_type_t *)&rsa_type)},
    {MP_ROM_QSTR(MP_QSTR_serialization), MP_ROM_PTR((mp_obj_type_t *)&serialization_type)},
    {MP_ROM_QSTR(MP_QSTR_twofactor), MP_ROM_PTR((mp_obj_type_t *)&twofactor_type)},
    {MP_ROM_QSTR(MP_QSTR_utils), MP_ROM_PTR((mp_obj_type_t *)&utils_type)},
    {MP_ROM_QSTR(MP_QSTR_x509), MP_ROM_PTR((mp_obj_type_t *)&x509_type)},
};

static MP_DEFINE_CONST_DICT(mp_module_ucryptography_globals, mp_module_ucryptography_globals_table);

const mp_obj_module_t mp_module_ucryptography = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_ucryptography_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cryptography, mp_module_ucryptography);
