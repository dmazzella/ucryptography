# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)
---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

### Compiling the cmodule into unix port

```bash
$ git clone https://github.com/micropython/micropython.git
$ cd micropython
micropython$ git submodule update --init --depth 1
# micropython$ cd lib/mbedtls
# micropython/lib/mbedtls$ git checkout mbedtls-2.28.1
# micropython/lib/mbedtls$ cd ../../
micropython$ git clone https://github.com/dmazzella/ucryptography.git usercmodule/ucryptography
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -j2 -C ports/unix/ MICROPY_SSL_AXTLS=0 MICROPY_SSL_MBEDTLS=1 USER_C_MODULES="$(pwd)/usercmodule"
```

```python
import cryptography
```

## Modoli supportati

- ciphers
  - AESGCM
  - Cipher
  - algorithms
    - AES
    - TripleDES
  - modes
    - CBC
    - ECB
    - GCM
- ec
  - ECDH
  - ECDSA
  - SECP256R1
  - SECP384R1
  - SECP521R1
  - EllipticCurvePublicKey
    - from_encoded_point
  - EllipticCurvePublicNumbers
  - EllipticCurvePrivateKey
  - EllipticCurvePrivateNumbers
  - generate_private_key
  - derive_private_key
- ed25519
  - Ed25519PrivateKey
  - Ed25519PublicKey
- exceptions
  - InvalidSignature
  - AlreadyFinalized
  - UnsupportedAlgorithm
  - InvalidKey
  - InvalidToken
- hashes
  - SHA1
  - SHA256
  - SHA384
  - SHA512
  - BLAKE2s
  - Hash
- hmac
  - HMAC
- padding
  - PKCS1v15
  - PSS
  - OAEP
  - MGF1
  - calculate_max_pss_salt_length
- rsa
  - RSAPublicKey
  - RSAPublicNumbers
  - RSAPrivateKey
  - RSAPrivateNumbers
  - rsa_crt_iqmp
  - rsa_crt_dmp1
  - rsa_crt_dmq1
  - rsa_recover_prime_factors
  - generate_private_key
- serialization
  - load_der_public_key
  - load_der_private_key
  - Encoding
    - DER
    - PEM
- twofactor
  - HOTP
  - TOTP
- utils
  - RFC6979
  - CipheredBlockDevice
  - Prehashed
  - constant_time_bytes_eq
  - bit_length
  - encode_dss_signature
  - decode_dss_signature
  - rsa_deduce_private_exponent
- version
  - get_number
  - get_string
  - get_string_full
  - check_feature
- x509
  - load_der_x509_certificate
  - Certificate

## Esempi
- [tests/cryptography](https://github.com/dmazzella/ucryptography/tree/master/tests/cryptography)
- [tests/ucryptography](https://github.com/dmazzella/ucryptography/tree/master/tests/ucryptography)
