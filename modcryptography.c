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

#if defined(MICROPY_PY_UCRYPTOGRAPHY)

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "py/objstr.h"
#include "py/objint.h"
#include "py/runtime.h"

#if !defined(MBEDTLS_USER_CONFIG_FILE)
#define MBEDTLS_USER_CONFIG_FILE "modcryptography_config.h"
#endif //MBEDTLS_USER_CONFIG_FILE

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif // MBEDTLS_CONFIG_FILE

#if defined(MBEDTLS_VERSION_C)
#include "mbedtls/version.h"

STATIC void version_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t version_get_number(void)
{
    return mp_obj_new_int(mbedtls_version_get_number());
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_version_get_number_obj, version_get_number);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_version_get_number_obj, MP_ROM_PTR(&mod_version_get_number_obj));

STATIC mp_obj_t version_get_string(void)
{
    vstr_t vstr_out;
    vstr_init_len(&vstr_out, sizeof(MBEDTLS_VERSION_STRING));
    mbedtls_version_get_string((char *)vstr_out.buf);
    return mp_obj_new_str_from_vstr(&mp_type_str, &vstr_out);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_version_get_string_obj, version_get_string);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_version_get_string_obj, MP_ROM_PTR(&mod_version_get_string_obj));

STATIC mp_obj_t version_get_string_full(void)
{
    vstr_t vstr_out;
    vstr_init_len(&vstr_out, sizeof(MBEDTLS_VERSION_STRING_FULL));
    mbedtls_version_get_string_full((char *)vstr_out.buf);
    return mp_obj_new_str_from_vstr(&mp_type_str, &vstr_out);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_version_get_string_full_obj, version_get_string_full);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_version_get_string_full_obj, MP_ROM_PTR(&mod_version_get_string_full_obj));

#if defined(MBEDTLS_VERSION_FEATURES)
STATIC mp_obj_t version_check_feature(mp_obj_t feature)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(feature, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError(NULL);
    }
    return mp_obj_new_bool(mbedtls_version_check_feature(bufinfo.buf) == 0);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_version_check_feature_obj, version_check_feature);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_version_check_feature_obj, MP_ROM_PTR(&mod_version_check_feature_obj));
#endif // MBEDTLS_VERSION_FEATURES

STATIC const mp_rom_map_elem_t version_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_get_number), MP_ROM_PTR(&mod_static_version_get_number_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_string), MP_ROM_PTR(&mod_static_version_get_string_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_string_full), MP_ROM_PTR(&mod_static_version_get_string_full_obj)},
#if defined(MBEDTLS_VERSION_FEATURES)
    {MP_ROM_QSTR(MP_QSTR_check_feature), MP_ROM_PTR(&mod_static_version_check_feature_obj)},
#endif // MBEDTLS_VERSION_FEATURES
};

STATIC MP_DEFINE_CONST_DICT(version_locals_dict, version_locals_dict_table);

STATIC mp_obj_type_t version_type = {
    {&mp_type_type},
    .name = MP_QSTR_version,
    .print = version_print,
    .locals_dict = (void *)&version_locals_dict,
};

#endif // MBEDTLS_VERSION_C

#if defined(MBEDTLS_X509_USE_C)
#include "mbedtls/x509.h"
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#endif //MBEDTLS_X509_CRT_PARSE_C

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_PK_PARSE_C)

typedef struct _mp_ec_curve_t
{
    mp_obj_base_t base;
} mp_ec_curve_t;

STATIC void ec_curve_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC const mp_rom_map_elem_t ec_curve_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_secp256r1)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(256)},
};

STATIC MP_DEFINE_CONST_DICT(ec_curve_locals_dict, ec_curve_locals_dict_table);

STATIC mp_obj_type_t ec_curve_type = {
    {&mp_type_type},
    .name = MP_QSTR_EllipticCurve,
    .print = ec_curve_print,
    .locals_dict = (void *)&ec_curve_locals_dict,
};

const mp_ec_curve_t mp_const_elliptic_curve_obj = {{&ec_curve_type}};

typedef struct _mp_ec_public_numbers_t
{
    mp_obj_base_t base;
    mp_ec_curve_t *curve;
    mp_obj_t x;
    mp_obj_t y;
} mp_ec_public_numbers_t;

STATIC void ec_public_numbers_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC void ec_public_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_public_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = &type->locals_dict->map;
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

STATIC const mp_rom_map_elem_t ec_public_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_x), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_y), MP_ROM_PTR(mp_const_none)},
};

STATIC MP_DEFINE_CONST_DICT(ec_public_numbers_locals_dict, ec_public_numbers_locals_dict_table);

STATIC mp_obj_type_t ec_public_numbers_type = {
    {&mp_type_type},
    .name = MP_QSTR_EllipticCurvePublicNumbers,
    .print = ec_public_numbers_print,
    .attr = ec_public_numbers_attr,
    .locals_dict = (void *)&ec_public_numbers_locals_dict,
};

typedef struct _mp_ec_private_numbers_t
{
    mp_obj_base_t base;
    mp_ec_public_numbers_t *public_numbers;
    mp_obj_t private_value;
} mp_ec_private_numbers_t;

STATIC void ec_private_numbers_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC void ec_private_numbers_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_ec_private_numbers_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = &type->locals_dict->map;
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

STATIC const mp_rom_map_elem_t ec_private_numbers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_private_value), MP_ROM_PTR(mp_const_none)},
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(mp_const_none)},
};

STATIC MP_DEFINE_CONST_DICT(ec_private_numbers_locals_dict, ec_private_numbers_locals_dict_table);

STATIC mp_obj_type_t ec_private_numbers_type = {
    {&mp_type_type},
    .name = MP_QSTR_EllipticCurvePrivateNumbers,
    .print = ec_private_numbers_print,
    .attr = ec_private_numbers_attr,
    .locals_dict = (void *)&ec_private_numbers_locals_dict,
};

typedef struct _mp_ec_public_key_t
{
    mp_obj_base_t base;
    mp_ec_public_numbers_t *public_numbers;
    mp_obj_t public_bytes;
} mp_ec_public_key_t;

STATIC void ec_public_key_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t ec_verify(mp_obj_t obj, mp_obj_t signature, mp_obj_t digest)
{
    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(signature, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError("SIGNATURE EMPTY");
    }

    mp_buffer_info_t bufinfo1;
    mp_get_buffer_raise(digest, &bufinfo1, MP_BUFFER_READ);
    if (!bufinfo1.len)
    {
        mp_raise_ValueError("DIGEST EMPTY");
    }

    return mp_obj_new_bool(0);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_ec_verify_obj, ec_verify);

STATIC mp_obj_t ec_public_numbers(mp_obj_t obj)
{
    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_numbers;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_numbers_obj, ec_public_numbers);

STATIC mp_obj_t ec_public_bytes(mp_obj_t obj)
{
    mp_ec_public_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_bytes;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_bytes_obj, ec_public_bytes);

STATIC const mp_rom_map_elem_t ec_public_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(MP_OBJ_FROM_PTR(&mp_const_elliptic_curve_obj))},
    {MP_ROM_QSTR(MP_QSTR_public_numbers), MP_ROM_PTR(&mod_ec_public_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_bytes), MP_ROM_PTR(&mod_ec_public_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_OBJ_FROM_PTR(&mod_ec_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(256)},
};

STATIC MP_DEFINE_CONST_DICT(ec_public_key_locals_dict, ec_public_key_locals_dict_table);

STATIC mp_obj_type_t ec_public_key_type = {
    {&mp_type_type},
    .name = MP_QSTR_EllipticCurvePublicKey,
    .print = ec_public_key_print,
    .locals_dict = (void *)&ec_public_key_locals_dict,
};

typedef struct _mp_ec_private_key_t
{
    mp_obj_base_t base;
    mp_ec_curve_t *curve;
    mp_ec_private_numbers_t *private_numbers;
    mp_ec_public_key_t *public_key;
    mp_obj_t private_bytes;
} mp_ec_private_key_t;

STATIC void ec_private_key_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t ec_private_numbers(mp_obj_t obj)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_numbers;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_private_numbers_obj, ec_private_numbers);

STATIC mp_obj_t ec_sign(mp_obj_t obj, mp_obj_t digest)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    (void)self;
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(digest, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError("DIGEST EMPTY");
    }

    return mp_obj_new_bool(0);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_ec_sign_obj, ec_sign);

STATIC mp_obj_t ec_public_key(mp_obj_t obj)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_public_key_obj, ec_public_key);

STATIC mp_obj_t ec_private_bytes(mp_obj_t obj)
{
    mp_ec_private_key_t *self = MP_OBJ_TO_PTR(obj);
    return self->private_bytes;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_ec_private_bytes_obj, ec_private_bytes);

STATIC const mp_rom_map_elem_t ec_private_key_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(MP_OBJ_FROM_PTR(&mp_const_elliptic_curve_obj))},
    {MP_ROM_QSTR(MP_QSTR_private_numbers), MP_ROM_PTR(&mod_ec_private_numbers_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mod_ec_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_private_bytes), MP_ROM_PTR(&mod_ec_private_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_ec_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_size), MP_ROM_INT(256)},
};

STATIC MP_DEFINE_CONST_DICT(ec_private_key_locals_dict, ec_private_key_locals_dict_table);

STATIC mp_obj_type_t ec_private_key_type = {
    {&mp_type_type},
    .name = MP_QSTR_EllipticCurvePrivateKey,
    .print = ec_private_key_print,
    .locals_dict = (void *)&ec_private_key_locals_dict,
};

STATIC mp_obj_t ec_parse_keypair(const mbedtls_ecp_keypair *ecp_keypair, bool private)
{
    vstr_t vstr_q_x;
    vstr_init_len(&vstr_q_x, mbedtls_mpi_size(&ecp_keypair->Q.X));
    mbedtls_mpi_write_binary(&ecp_keypair->Q.X, (unsigned char *)vstr_q_x.buf, vstr_len(&vstr_q_x));

    vstr_t vstr_q_y;
    vstr_init_len(&vstr_q_y, mbedtls_mpi_size(&ecp_keypair->Q.Y));
    mbedtls_mpi_write_binary(&ecp_keypair->Q.Y, (unsigned char *)vstr_q_y.buf, vstr_len(&vstr_q_y));

    mp_ec_public_key_t *EllipticCurvePublicKey = m_new_obj(mp_ec_public_key_t);
    EllipticCurvePublicKey->base.type = &ec_public_key_type;

    mp_ec_curve_t *EllipticCurve = m_new_obj(mp_ec_curve_t);
    EllipticCurve->base.type = &ec_curve_type;

    mp_ec_public_numbers_t *EllipticCurvePublicNumbers = m_new_obj(mp_ec_public_numbers_t);
    EllipticCurvePublicNumbers->base.type = &ec_public_numbers_type;
    EllipticCurvePublicNumbers->curve = EllipticCurve;
    EllipticCurvePublicNumbers->x = mp_obj_int_from_bytes_impl(true, vstr_len(&vstr_q_x), (const byte *)vstr_q_x.buf);
    EllipticCurvePublicNumbers->y = mp_obj_int_from_bytes_impl(true, vstr_len(&vstr_q_y), (const byte *)vstr_q_y.buf);

    EllipticCurvePublicKey->public_numbers = EllipticCurvePublicNumbers;

    size_t olen = 0;
    vstr_t vstr_public_bytes;
    vstr_init_len(&vstr_public_bytes, mbedtls_mpi_size(&ecp_keypair->Q.X) + mbedtls_mpi_size(&ecp_keypair->Q.Y) + 1);
    mbedtls_ecp_point_write_binary(&ecp_keypair->grp, &ecp_keypair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (unsigned char *)vstr_public_bytes.buf, vstr_len(&vstr_public_bytes));

    EllipticCurvePublicKey->public_bytes = mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr_public_bytes);

    if (private)
    {
        vstr_t vstr_private_bytes;
        vstr_init_len(&vstr_private_bytes, mbedtls_mpi_size(&ecp_keypair->d));
        mbedtls_mpi_write_binary(&ecp_keypair->d, (unsigned char *)vstr_private_bytes.buf, vstr_len(&vstr_private_bytes));

        mp_ec_private_numbers_t *EllipticCurvePrivateNumbers = m_new_obj(mp_ec_private_numbers_t);
        EllipticCurvePrivateNumbers->base.type = &ec_private_numbers_type;
        EllipticCurvePrivateNumbers->private_value = mp_obj_int_from_bytes_impl(true, vstr_len(&vstr_private_bytes), (const byte *)vstr_private_bytes.buf);
        EllipticCurvePrivateNumbers->public_numbers = EllipticCurvePublicNumbers;

        mp_ec_private_key_t *EllipticCurvePrivateKey = m_new_obj(mp_ec_private_key_t);
        EllipticCurvePrivateKey->base.type = &ec_private_key_type;
        EllipticCurvePrivateKey->curve = EllipticCurve;
        EllipticCurvePrivateKey->private_numbers = EllipticCurvePrivateNumbers;
        EllipticCurvePrivateKey->public_key = EllipticCurvePublicKey;
        EllipticCurvePrivateKey->private_bytes = mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr_private_bytes);
        return EllipticCurvePrivateKey;
    }
    else
    {
        return EllipticCurvePublicKey;
    }
}

#endif // MBEDTLS_PK_PARSE_C

typedef struct _mp_hash_algorithm_t
{
    mp_obj_base_t base;
} mp_hash_algorithm_t;

STATIC void hash_algorithm_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC const mp_rom_map_elem_t hash_algorithm_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_name), MP_ROM_QSTR(MP_QSTR_sha256)},
};

STATIC MP_DEFINE_CONST_DICT(hash_algorithm_locals_dict, hash_algorithm_locals_dict_table);

STATIC mp_obj_type_t hash_algorithm_type = {
    {&mp_type_type},
    .name = MP_QSTR_HashAlgorithm,
    .print = hash_algorithm_print,
    .locals_dict = (void *)&hash_algorithm_locals_dict,
};

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
    mp_hash_algorithm_t *signature_hash_algorithm;
    mp_obj_t extensions;
    mp_obj_t public_bytes;
    mp_ec_public_key_t *public_key;
    mp_obj_t tbs_certificate_bytes;
} mp_x509_certificate_t;

STATIC void x509_certificate_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

#if defined(MBEDTLS_PK_PARSE_C)
STATIC mp_obj_t x509_public_key(mp_obj_t obj)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_key;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_public_key_obj, x509_public_key);
#endif

STATIC mp_obj_t x509_public_bytes(mp_obj_t obj)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(obj);
    return self->public_bytes;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_public_bytes_obj, x509_public_bytes);

STATIC void x509_certificate_attr(mp_obj_t obj, qstr attr, mp_obj_t *dest)
{
    mp_x509_certificate_t *self = MP_OBJ_TO_PTR(obj);
    if (dest[0] == MP_OBJ_NULL)
    {
        mp_obj_type_t *type = mp_obj_get_type(obj);
        mp_map_t *locals_map = &type->locals_dict->map;
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

STATIC const mp_rom_map_elem_t x509_certificate_locals_dict_table[] = {
#if defined(MBEDTLS_PK_PARSE_C)
    {MP_ROM_QSTR(MP_QSTR_public_key), MP_ROM_PTR(&mod_x509_public_key_obj)},
#endif
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

STATIC MP_DEFINE_CONST_DICT(x509_certificate_locals_dict, x509_certificate_locals_dict_table);

STATIC mp_obj_type_t x509_certificate_type = {
    {&mp_type_type},
    .name = MP_QSTR_Certificate,
    .print = x509_certificate_print,
    .attr = x509_certificate_attr,
    .locals_dict = (void *)&x509_certificate_locals_dict,
};

STATIC void x509_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t x509_crt_parse_oid(const mbedtls_asn1_buf *o, const mp_obj_type_t *type)
{
    unsigned int value = 0;
    vstr_t vstr_oid;
    vstr_init(&vstr_oid, 0);

    for (int i = 0; i < o->len; i++)
    {
        if (i == 0)
        {
            vstr_printf(&vstr_oid, "%d.%d", o->p[0] / 40, o->p[0] % 40);
        }

        if (((value << 7) >> 7) != value)
        {
            mp_raise_ValueError("OID BUF TOO SMALL");
        }

        value <<= 7;
        value += o->p[i] & 0x7F;

        if (!(o->p[i] & 0x80))
        {
            vstr_printf(&vstr_oid, ".%d", value);
            value = 0;
        }
    }

    return mp_obj_new_str_from_vstr(type, &vstr_oid);
}

STATIC mp_obj_t x509_crt_parse_time(const mbedtls_x509_time *t)
{
    vstr_t vstr_time;
    vstr_init(&vstr_time, 0);
    vstr_printf(&vstr_time, "%04d-%02d-%02d %02d:%02d:%02d", t->year, t->mon, t->day, t->hour, t->min, t->sec);
    return mp_obj_new_str_from_vstr(&mp_type_str, &vstr_time);
}

STATIC mp_obj_t x509_crt_parse_name(const mbedtls_x509_name *dn)
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

STATIC mp_obj_t x509_crt_parse_ext_key_usage(const mbedtls_x509_sequence *extended_key_usage)
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

STATIC mp_obj_t x509_crt_parse_key_usage(const unsigned int ku)
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

STATIC mp_obj_t x509_crt_parse_der(mp_obj_t certificate)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(certificate, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError("CERTIFICATE EMPTY");
    }
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der_nocopy(&crt, (const byte *)bufinfo.buf, bufinfo.len) != 0)
    {
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError("CERTIFICATE FORMAT");
    }

    // vstr_t vstr_crt;
    // vstr_init_len(&vstr_crt, crt.raw.len);
    // mbedtls_x509_crt_info(vstr_crt.buf, vstr_len(&vstr_crt), "", &crt);
    // printf("certificate info: %s\n", vstr_crt.buf);

    if (crt.sig_md != MBEDTLS_MD_SHA256)
    {
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError("SIGNATURE HASH ALGORITHM UNSUPPORTED (ONLY SHA256 IS SUPPORTED)");
    }

    if (crt.sig_pk != MBEDTLS_PK_ECDSA)
    {
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError("SIGNATURE PUBLIC KEY ALGORITHM UNSUPPORTED (ONLY ECDSA IS SUPPORTED)");
    }

    mp_obj_t extensions = mp_obj_new_dict(0);
    mp_obj_dict_store(extensions, MP_ROM_QSTR(MP_QSTR_extended_key_usage), x509_crt_parse_ext_key_usage(&crt.ext_key_usage));
    mp_obj_dict_store(extensions, MP_ROM_QSTR(MP_QSTR_key_usage), x509_crt_parse_key_usage(crt.key_usage));

    mp_hash_algorithm_t *HashAlgorithm = m_new_obj(mp_hash_algorithm_t);
    HashAlgorithm->base.type = &hash_algorithm_type;

    mp_x509_certificate_t *Certificate = m_new_obj(mp_x509_certificate_t);
    Certificate->base.type = &x509_certificate_type;
    Certificate->version = mp_obj_new_int(crt.version);
    Certificate->serial_number = mp_obj_int_from_bytes_impl(true, crt.serial.len, crt.serial.p);
    Certificate->not_valid_before = x509_crt_parse_time(&crt.valid_from);
    Certificate->not_valid_after = x509_crt_parse_time(&crt.valid_to);
    Certificate->subject = x509_crt_parse_name(&crt.subject);
    Certificate->issuer = x509_crt_parse_name(&crt.issuer);
    Certificate->signature = mp_obj_new_bytes(crt.sig.p, crt.sig.len);
    Certificate->signature_algorithm_oid = x509_crt_parse_oid(&crt.sig_oid, &mp_type_str);
    Certificate->signature_hash_algorithm = HashAlgorithm;
    Certificate->extensions = extensions;
    Certificate->tbs_certificate_bytes = mp_obj_new_bytes(crt.tbs.p, crt.tbs.len);
    Certificate->public_bytes = mp_obj_new_bytes(crt.pk_raw.p, crt.pk_raw.len);

#if defined(MBEDTLS_PK_PARSE_C)
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, crt.pk_raw.p, crt.pk_raw.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError("PUBLIC KEY FORMAT");
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY)
    {
        mbedtls_pk_free(&pk);
        mbedtls_x509_crt_free(&crt);
        mp_raise_ValueError("PUBLIC KEY UNSUPPORTED (ONLY EC KEY IS SUPPORTED)");
    }

    Certificate->public_key = ec_parse_keypair(mbedtls_pk_ec(pk), false);

    mbedtls_pk_free(&pk);
#endif // MBEDTLS_PK_PARSE_C

    mbedtls_x509_crt_free(&crt);

    return Certificate;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_x509_crt_parse_der_obj, x509_crt_parse_der);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_x509_crt_parse_der_obj, MP_ROM_PTR(&mod_x509_crt_parse_der_obj));
#endif // MBEDTLS_X509_CRT_PARSE_C

STATIC const mp_rom_map_elem_t x509_locals_dict_table[] = {
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    {MP_ROM_QSTR(MP_QSTR_load_der_x509_certificate), MP_ROM_PTR(&mod_static_x509_crt_parse_der_obj)},
#endif //MBEDTLS_X509_CRT_PARSE_C
};

STATIC MP_DEFINE_CONST_DICT(x509_locals_dict, x509_locals_dict_table);

STATIC mp_obj_type_t x509_type = {
    {&mp_type_type},
    .name = MP_QSTR_x509,
    .print = x509_print,
    .locals_dict = (void *)&x509_locals_dict,
};
#endif // MBEDTLS_X509_USE_C

#if defined(MBEDTLS_PK_PARSE_C)
STATIC void serialization_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t pk_parse_public_key(mp_obj_t public_key)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(public_key, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError("PUBLIC KEY EMPTY");
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, (const byte *)bufinfo.buf, bufinfo.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_ValueError("PUBLIC KEY FORMAT");
    }

    mp_obj_t pub_key = ec_parse_keypair(mbedtls_pk_ec(pk), false);

    mbedtls_pk_free(&pk);
    return pub_key;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_pk_parse_public_key_obj, pk_parse_public_key);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_pk_parse_public_key_obj, MP_ROM_PTR(&mod_pk_parse_public_key_obj));

STATIC mp_obj_t pk_parse_key(mp_obj_t private_key, mp_obj_t password)
{
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(private_key, &bufinfo, MP_BUFFER_READ);
    if (!bufinfo.len)
    {
        mp_raise_ValueError("PRIVATE KEY EMPTY");
    }

    mp_buffer_info_t bufinfo1;
    bool use_password = mp_get_buffer(password, &bufinfo1, MP_BUFFER_READ);
    if (use_password && !bufinfo1.len)
    {
        mp_raise_ValueError("PRIVATE KEY EMPTY");
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_key(&pk, (const byte *)bufinfo.buf, bufinfo.len, (use_password ? (const byte *)bufinfo1.buf : NULL), bufinfo1.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_ValueError("PRIVATE KEY FORMAT");
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY)
    {
        mbedtls_pk_free(&pk);
        mp_raise_ValueError("PRIVATE KEY UNSUPPORTED (ONLY EC KEY IS SUPPORTED)");
    }

    mp_obj_t priv_key = ec_parse_keypair(mbedtls_pk_ec(pk), true);

    mbedtls_pk_free(&pk);
    return priv_key;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_pk_parse_key_obj, pk_parse_key);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_pk_parse_key_obj, MP_ROM_PTR(&mod_pk_parse_key_obj));

STATIC const mp_rom_map_elem_t serialization_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_load_der_public_key), MP_ROM_PTR(&mod_static_pk_parse_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_load_der_private_key), MP_ROM_PTR(&mod_static_pk_parse_key_obj)},
};

STATIC MP_DEFINE_CONST_DICT(serialization_locals_dict, serialization_locals_dict_table);

STATIC mp_obj_type_t serialization_type = {
    {&mp_type_type},
    .name = MP_QSTR_serialization,
    .print = serialization_print,
    .locals_dict = (void *)&serialization_locals_dict,
};
#endif //MBEDTLS_PK_PARSE_C

STATIC const mp_map_elem_t mp_module_ucryptography_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_cryptography)},
#if defined(MBEDTLS_VERSION_C)
    {MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&version_type)},
#endif // MBEDTLS_VERSION_FEATURES
#if defined(MBEDTLS_X509_USE_C)
    {MP_ROM_QSTR(MP_QSTR_x509), MP_ROM_PTR(&x509_type)},
    {MP_ROM_QSTR(MP_QSTR_Certificate), MP_ROM_PTR(&x509_certificate_type)},
    {MP_ROM_QSTR(MP_QSTR_HashAlgorithm), MP_ROM_PTR(&hash_algorithm_type)},
#endif // MBEDTLS_X509_USE_C
#if defined(MBEDTLS_PK_PARSE_C)
    {MP_ROM_QSTR(MP_QSTR_serialization), MP_ROM_PTR(&serialization_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurve), MP_ROM_PTR(&ec_curve_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePublicKey), MP_ROM_PTR(&ec_public_key_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePublicNumbers), MP_ROM_PTR(&ec_public_numbers_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePrivateKey), MP_ROM_PTR(&ec_private_key_type)},
    {MP_ROM_QSTR(MP_QSTR_EllipticCurvePrivateNumbers), MP_ROM_PTR(&ec_private_numbers_type)},
#endif //MBEDTLS_PK_PARSE_C
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ucryptography_globals, mp_module_ucryptography_globals_table);

const mp_obj_module_t mp_module_ucryptography = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_ucryptography_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cryptography, mp_module_ucryptography, MICROPY_PY_UCRYPTOGRAPHY);

#endif // MICROPY_PY_UCRYPTOGRAPHY