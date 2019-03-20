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

STATIC void x509_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)

STATIC mp_obj_t x509_crt_parse_time(const mbedtls_x509_time *t)
{
    vstr_t vstr_time;
    vstr_init(&vstr_time, 0);
    vstr_printf(&vstr_time, "%04d-%02d-%02d %02d:%02d:%02d", t->year, t->mon, t->day, t->hour, t->min, t->sec);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr_time);
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
        mp_obj_dict_store(rdn_dict, mp_obj_new_str_via_qstr(short_name, strlen(short_name)), mp_obj_new_bytes(name->val.p, name->val.len));

        name = name->next;
    }
    return rdn_dict;
}

STATIC mp_obj_t x509_crt_parse_oid(const mbedtls_x509_crt *crt)
{
    const mbedtls_asn1_buf *o = &crt->sig_oid;
    unsigned int value = 0;
    vstr_t vstr_oid;
    vstr_init(&vstr_oid, 0);

    for (int i = 0; i < o->len; i++)
    {
        if (i == 0) {
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
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr_oid);
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

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, crt.pk_raw.p, crt.pk_raw.len) != 0)
    {
        mbedtls_pk_free(&pk);
        mp_raise_ValueError("KEY FORMAT");
    }

    mp_obj_t cert = mp_obj_new_dict(0);
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_version), mp_obj_new_int(crt.version));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_serial_number), mp_obj_new_bytes(crt.serial.p, crt.serial.len));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_not_valid_before), x509_crt_parse_time(&crt.valid_from));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_not_valid_after), x509_crt_parse_time(&crt.valid_to));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_subject), x509_crt_parse_name(&crt.subject));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_issuer), x509_crt_parse_name(&crt.issuer));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_signature), mp_obj_new_bytes(crt.sig.p, crt.sig.len));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_tbs_certificate_bytes), mp_obj_new_bytes(crt.tbs.p, crt.tbs.len));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_public_key), mp_obj_new_bytes(crt.pk_raw.p, crt.pk_raw.len));
    mp_obj_dict_store(cert, MP_ROM_QSTR(MP_QSTR_signature_algorithm_oid), x509_crt_parse_oid(&crt));

    // vstr_t vstr_crt;
    // vstr_init_len(&vstr_crt, crt.raw.len);
    // mbedtls_x509_crt_info(vstr_crt.buf, vstr_len(&vstr_crt), "", &crt);
    // printf("certificate info: %s\n", vstr_crt.buf);

    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);
    return cert;
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

STATIC const mp_map_elem_t mp_module_ucryptography_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_cryptography)},
#if defined(MBEDTLS_VERSION_C)
    {MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&version_type)},
#endif // MBEDTLS_VERSION_FEATURES
#if defined(MBEDTLS_X509_USE_C)
    {MP_ROM_QSTR(MP_QSTR_x509), MP_ROM_PTR(&x509_type)},
#endif // MBEDTLS_X509_USE_C
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ucryptography_globals, mp_module_ucryptography_globals_table);

const mp_obj_module_t mp_module_ucryptography = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_ucryptography_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cryptography, mp_module_ucryptography, MICROPY_PY_UCRYPTOGRAPHY);

#endif // MICROPY_PY_UCRYPTOGRAPHY