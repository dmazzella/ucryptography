/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017-2026 Damiano Mazzella
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

#ifndef MODCRYPTOGRAPHY_FEATURES_H
#define MODCRYPTOGRAPHY_FEATURES_H

// ucryptography feature toggles: 1 = compiled in, 0 = stubbed (constructing the
// feature raises NotImplementedError naming the flag to enable). A board or a
// -D on the command line may pre-define any of these to override the default.

// --- Hashes ---
#ifndef MICROPY_PY_UCRYPTOGRAPHY_SHA1
#define MICROPY_PY_UCRYPTOGRAPHY_SHA1 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_SHA256
#define MICROPY_PY_UCRYPTOGRAPHY_SHA256 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_SHA384
#define MICROPY_PY_UCRYPTOGRAPHY_SHA384 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_SHA512
#define MICROPY_PY_UCRYPTOGRAPHY_SHA512 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_BLAKE2S
#define MICROPY_PY_UCRYPTOGRAPHY_BLAKE2S (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_HASH
#define MICROPY_PY_UCRYPTOGRAPHY_HASH (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_HMAC
#define MICROPY_PY_UCRYPTOGRAPHY_HMAC (1)
#endif

// --- Symmetric ciphers ---
#ifndef MICROPY_PY_UCRYPTOGRAPHY_AES
#define MICROPY_PY_UCRYPTOGRAPHY_AES (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_AESGCM
#define MICROPY_PY_UCRYPTOGRAPHY_AESGCM (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_TRIPLEDES
#define MICROPY_PY_UCRYPTOGRAPHY_TRIPLEDES (1)
#endif

// --- RSA padding ---
#ifndef MICROPY_PY_UCRYPTOGRAPHY_PKCS1V15
#define MICROPY_PY_UCRYPTOGRAPHY_PKCS1V15 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_MGF1
#define MICROPY_PY_UCRYPTOGRAPHY_MGF1 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_OAEP
#define MICROPY_PY_UCRYPTOGRAPHY_OAEP (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_PSS
#define MICROPY_PY_UCRYPTOGRAPHY_PSS (1)
#endif

// --- Public-key / X.509 ---
#ifndef MICROPY_PY_UCRYPTOGRAPHY_RSA
#define MICROPY_PY_UCRYPTOGRAPHY_RSA (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_EC
#define MICROPY_PY_UCRYPTOGRAPHY_EC (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_ED25519
#define MICROPY_PY_UCRYPTOGRAPHY_ED25519 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_X509
#define MICROPY_PY_UCRYPTOGRAPHY_X509 (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE
#define MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE (1)
#endif
#ifndef MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
#define MICROPY_PY_UCRYPTOGRAPHY_X509_CSR (1)
#endif

// --- Miscellaneous ---
#ifndef MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR
#define MICROPY_PY_UCRYPTOGRAPHY_TWOFACTOR (1)
#endif

// --- Inter-feature dependencies (keep after the defaults above) ---

// OAEP and PSS both require an MGF1 instance.
#if !MICROPY_PY_UCRYPTOGRAPHY_MGF1
#undef MICROPY_PY_UCRYPTOGRAPHY_OAEP
#define MICROPY_PY_UCRYPTOGRAPHY_OAEP (0)
#undef MICROPY_PY_UCRYPTOGRAPHY_PSS
#define MICROPY_PY_UCRYPTOGRAPHY_PSS (0)
#endif

// x509 certificate creation re-parses the signed DER, so it needs x509 read.
// The CSR object graph (subject Name, Extensions, OIDs) also builds on x509 read.
#if !MICROPY_PY_UCRYPTOGRAPHY_X509
#undef MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE
#define MICROPY_PY_UCRYPTOGRAPHY_X509_CREATE (0)
#undef MICROPY_PY_UCRYPTOGRAPHY_X509_CSR
#define MICROPY_PY_UCRYPTOGRAPHY_X509_CSR (0)
#endif

#endif // MODCRYPTOGRAPHY_FEATURES_H
