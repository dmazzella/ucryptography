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

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "py/objstr.h"
#include "py/runtime.h"

#if defined(MICROPY_PY_UCRYPTOGRAPHY)

#if !defined(MBEDTLS_USER_CONFIG_FILE)
#define MBEDTLS_USER_CONFIG_FILE "modcryptography_config.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_exit exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MICROPY_PY_UCRYPTOGRAPHY_VERSION)
#include "mbedtls/version.h"

STATIC void version_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind)
{
    (void)kind;
    mp_printf(print, mp_obj_get_type_str(self_in));
}

STATIC mp_obj_t version_get_string_full(void)
{
    vstr_t vstr_out;
    vstr_init_len(&vstr_out, sizeof(MBEDTLS_VERSION_STRING_FULL));
    mbedtls_version_get_string_full((char *)vstr_out.buf);
    return mp_obj_new_str_from_vstr(&mp_type_str, &vstr_out);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(mod_version_get_string_full_obj, version_get_string_full);
STATIC MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_version_get_string_full_obj, MP_ROM_PTR(&mod_version_get_string_full_obj));

STATIC const mp_rom_map_elem_t version_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_version_get_string_full), MP_ROM_PTR(&mod_static_version_get_string_full_obj)},
};

STATIC MP_DEFINE_CONST_DICT(version_locals_dict, version_locals_dict_table);

STATIC mp_obj_type_t version_type = {
    {&mp_type_type},
    .name = MP_QSTR_version,
    .print = version_print,
    .locals_dict = (void *)&version_locals_dict,
};

#endif

STATIC const mp_map_elem_t mp_module_ucryptography_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_cryptography)},
#if defined(MICROPY_PY_UCRYPTOGRAPHY_VERSION)
    {MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&version_type)},
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ucryptography_globals, mp_module_ucryptography_globals_table);

const mp_obj_module_t mp_module_ucryptography = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_ucryptography_globals,
};

// Source files #include'd here to make sure they're compiled in
// only if module is enabled by config setting.
#if defined(MICROPY_PY_UCRYPTOGRAPHY_VERSION)
#include "mbed-crypto/library/version.c"
#endif

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cryptography, mp_module_ucryptography, MICROPY_PY_UCRYPTOGRAPHY);

#endif // MICROPY_PY_UCRYPTOGRAPHY