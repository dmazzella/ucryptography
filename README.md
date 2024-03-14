# ucryptography

<b><i>Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)</i></b>

> [!TIP]
> If you find **ucryptography** useful, consider :star: this project
> and why not ... [Buy me a coffee](https://www.buymeacoffee.com/damianomazp) :smile:

## Basic usage

```python
from cryptography import rsa, hashes, padding

message = b"A message I want to sign"
chosen_hash = hashes.SHA256()

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(chosen_hash), salt_length=chosen_hash.digest_size
    ),
    chosen_hash,
)
public_key = private_key.public_key()
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(chosen_hash), salt_length=chosen_hash.digest_size
    ),
    chosen_hash,
)
```

## More examples
- [tests/cryptography](https://github.com/dmazzella/ucryptography/tree/master/tests/cryptography)

## How to build

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

***

> [!IMPORTANT]
> Currently needs a patch to the file `extmod/mbedtls/mbedtls_config_common.h` to enable all its functionality.

<details><summary><b>diff</b></summary>
<p>

```diff
diff --git a/extmod/mbedtls/mbedtls_config_common.h b/extmod/mbedtls/mbedtls_config_common.h
index db1562f27..d938c829a 100644
--- a/extmod/mbedtls/mbedtls_config_common.h
+++ b/extmod/mbedtls/mbedtls_config_common.h
@@ -46,9 +46,11 @@
 #define MBEDTLS_ECP_DP_SECP256K1_ENABLED
 #define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
 #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
+#define MBEDTLS_BASE64_C
 #define MBEDTLS_CAN_ECDH
 #define MBEDTLS_PK_CAN_ECDSA_SIGN
 #define MBEDTLS_PKCS1_V15
+#define MBEDTLS_PKCS1_V21
 #define MBEDTLS_SHA256_SMALLER
 #define MBEDTLS_SSL_PROTO_TLS1
 #define MBEDTLS_SSL_PROTO_TLS1_1
@@ -67,17 +69,23 @@
 #define MBEDTLS_BIGNUM_C
 #define MBEDTLS_CIPHER_C
 #define MBEDTLS_CTR_DRBG_C
+#define MBEDTLS_DES_C
 #define MBEDTLS_ECDH_C
 #define MBEDTLS_ECDSA_C
 #define MBEDTLS_ECP_C
 #define MBEDTLS_ENTROPY_C
 #define MBEDTLS_ERROR_C
+#define MBEDTLS_GCM_C
+#define MBEDTLS_GENPRIME
 #define MBEDTLS_MD_C
 #define MBEDTLS_MD5_C
 #define MBEDTLS_OID_C
+#define MBEDTLS_PEM_PARSE_C
+#define MBEDTLS_PEM_WRITE_C
 #define MBEDTLS_PKCS5_C
 #define MBEDTLS_PK_C
 #define MBEDTLS_PK_PARSE_C
+#define MBEDTLS_PK_WRITE_C
 #define MBEDTLS_PLATFORM_C
 #define MBEDTLS_RSA_C
 #define MBEDTLS_SHA1_C
```
</p>
</details>

***

<details><summary><b>UNIX port (coverage)</b></summary>
<p>

```bash
$ git clone https://github.com/micropython/micropython.git
$ cd micropython
micropython$ git submodule update --init --depth 1
micropython$ git clone https://github.com/dmazzella/ucryptography.git usercmodule/ucryptography
micropython$ git apply usercmodule/ucryptography/patches/extmod__mbedtls__mbedtls_config_common.h.patch
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -j2 -C ports/unix/ VARIANT="coverage" MICROPY_SSL_AXTLS=0 MICROPY_SSL_MBEDTLS=1 USER_C_MODULES="$(pwd)/usercmodule"
```
</p>
</details>

<details><summary><b>ESP32 port (ESP32_GENERIC_C3)</b></summary>
<p>

```bash
$ git clone https://github.com/micropython/micropython.git
$ cd micropython
micropython$ git submodule update --init --depth 1
micropython$ git clone https://github.com/dmazzella/ucryptography.git usercmodule/ucryptography
micropython$ git apply usercmodule/ucryptography/patches/extmod__mbedtls__mbedtls_config_common.h.patch
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -C ports/esp32 BOARD=ESP32_GENERIC_C3 USER_C_MODULES="$(pwd)/usercmodule/ucryptography/micropython.cmake"
```
</p>
</details>

<details><summary><b>STM32 port (ARDUINO_PORTENTA_H7)</b></summary>
<p>

```bash
$ git clone https://github.com/micropython/micropython.git
$ cd micropython
micropython$ git submodule update --init --depth 1
micropython$ git clone https://github.com/dmazzella/ucryptography.git usercmodule/ucryptography
micropython$ git apply usercmodule/ucryptography/patches/extmod__mbedtls__mbedtls_config_common.h.patch
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -C ports/stm32 BOARD=ARDUINO_PORTENTA_H7 USER_C_MODULES="$(pwd)/usercmodule/ucryptography/micropython.cmake"
```
</p>
</details>


## Goals 

![In progress](https://progress-bar.dev/100/?title=completed)

- [x] ciphers
  - [x] AESGCM
  - [x] Cipher
  - [x] algorithms
    - [x] AES
    - [x] TripleDES
  - [x] modes
    - [x] CBC
    - [x] ECB
    - [x] GCM
- [x] ec
  - [x] ECDH
  - [x] ECDSA
  - [x] SECP256R1
  - [x] SECP384R1
  - [x] SECP521R1
  - [x] EllipticCurvePublicKey
    - [x] from_encoded_point
  - [x] EllipticCurvePublicNumbers
  - [x] EllipticCurvePrivateKey
  - [x] EllipticCurvePrivateNumbers
  - [x] generate_private_key
  - [x] derive_private_key
- [x] ed25519
  - [x] Ed25519PrivateKey
  - [x] Ed25519PublicKey
- [x] exceptions
  - [x] InvalidSignature
  - [x] AlreadyFinalized
  - [x] UnsupportedAlgorithm
  - [x] InvalidKey
  - [x] InvalidToken
- [x] hashes
  - [x] SHA1
  - [x] SHA256
  - [x] SHA384
  - [x] SHA512
  - [x] BLAKE2s
  - [x] Hash
- [x] hmac
  - [x] HMAC
- [x] padding
  - [x] PKCS1v15
  - [x] PSS
  - [x] OAEP
  - [x] MGF1
  - [x] calculate_max_pss_salt_length
- [x] rsa
  - [x] RSAPublicKey
  - [x] RSAPublicNumbers
  - [x] RSAPrivateKey
  - [x] RSAPrivateNumbers
  - [x] rsa_crt_iqmp
  - [x] rsa_crt_dmp1
  - [x] rsa_crt_dmq1
  - [x] rsa_recover_prime_factors
  - [x] generate_private_key
- [x] serialization
  - [x] load_der_public_key
  - [x] load_der_private_key
  - [x] NoEncryption
  - [x] Encoding
    - [x] DER
    - [x] PEM
    - [x] X962
    - [x] Raw
  - [x] PublicFormat
    - [x] SubjectPublicKeyInfo
    - [x] UncompressedPoint
    - [x] Raw
  - [x] PrivateFormat
    - [x] TraditionalOpenSSL
    - [x] Raw
- [x] twofactor
  - [x] HOTP
  - [x] TOTP
- [x] utils
  - [x] RFC6979
  - [x] Prehashed
  - [x] constant_time_bytes_eq
  - [x] bit_length
  - [x] encode_dss_signature
  - [x] decode_dss_signature
  - [x] rsa_deduce_private_exponent
- [x] x509
  - [x] load_der_x509_certificate
  - [x] Certificate
