# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)
---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

<details><summary><b>Compiling the cmodule into unix port</b></summary>
<p>

**Warning**
Currently needs a patch to the file `extmod/mbedtls/mbedtls_config_common.h` to enable all its functionality.

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
micropython$ make -j2 -C ports/unix/ MICROPY_PY_BTREE=0 MICROPY_SSL_MBEDTLS=1 USER_C_MODULES="$(pwd)/usercmodule"
```
</p>
</details>

## Usage:

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

## Examples:
- [tests/cryptography](https://github.com/dmazzella/ucryptography/tree/master/tests/cryptography)
- [tests/ucryptography](https://github.com/dmazzella/ucryptography/tree/master/tests/ucryptography)

## Goals:

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
  v load_der_public_key
  v load_der_private_key
  - [x] Encoding
    - [x] DER
    - [x] PEM
- [x] twofactor
  - [x] HOTP
  - [x] TOTP
- [x] utils
  - [x] RFC6979
  - [x] CipheredBlockDevice
  - [x] Prehashed
  - [x] constant_time_bytes_eq
  - [x] bit_length
  - [x] encode_dss_signature
  - [x] decode_dss_signature
  - [x] rsa_deduce_private_exponent
- [x] version
  - [x] get_number
  - [x] get_string
  - [x] get_string_full
  - [x] check_feature
- [x] x509
  - [x] load_der_x509_certificate
  - [x] Certificate
