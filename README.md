# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)
---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

```python
import cryptography
```

## Modoli supportati

- ciphers
  - AESGCM
  - Cipher
  - algorithms
    - AES
  - modes
    - CBC
    - GCM
- ec
  - ECDH
  - ECDSA
  - SECP256R1
  - SECP384R1
  - SECP521R1
  - EllipticCurvePublicKey
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
  - CipheredBlockDevice
  - Prehashed
  - constant_time_bytes_eq
  - bit_length
  - encode_dss_signature
  - decode_dss_signature
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
