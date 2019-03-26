# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto/)
---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

```python
import cryptography
```

# API

## Classes
- ### **EllipticCurve**:
    - name -> **str**
        - _"secp256r1"_
    - key_size -> **int**
        - _256_

- ### **EllipticCurvePublicNumbers**:
    - curve -> **EllipticCurve**
    - x -> **int**
    - y -> **int**

- ### **EllipticCurvePrivateNumbers**:
    - public_numbers -> **EllipticCurvePublicNumbers**
    - private_value -> **int**

- ### **EllipticCurvePublicKey**:
    - public_numbers -> **EllipticCurvePublicNumbers**
    - public_bytes -> **bytes**
    - verify(signature:~~**tuple**(r:**int**, s:**int**)~~**bytes**, digest: **bytes**, ~~signature_algorithm:**bytes**~~) -> ~~raise: **InvalidSignature**~~ **bool**
    - key_size -> **int**
        - _256_

- ### **EllipticCurvePrivateKey**:
    - curve -> **EllipticCurve**
    - public_key -> **EllipticCurvePublicKey**
    - private_numbers -> **EllipticCurvePrivateNumbers**
    - private_bytes -> **bytes**
    - sign(digest: **bytes**, ~~signature_algorithm:**bytes**~~) -> **bytes**
    - key_size -> **int**
        - _256_

- **HashAlgorithm**:
    - name -> **str**
        - _"sha256"_

- ### **Certificate**:
    - version -> **int**
    - serial_number -> **int**
    - public_key -> **EllipticCurvePublicKey**
    - not_valid_before -> **str**
    - not_valid_after -> **str**
    - issuer -> **dict**
    - subject -> **dict**
    - signature_algorithm_oid -> **str**
    - signature_hash_algorithm -> **HashAlgorithm**
    - ~~fingerprint -> **bytes**~~
    - extensions -> **dict**
    - signature -> **bytes**
    - tbs_certificate_bytes -> **bytes**
    - public_bytes -> **bytes**

## Modules

- ### **cryptography.serialization**:
    ```python
    cryptography.serialization.load_der_public_key(der: bytes) -> EllipticCurvePublicKey
    cryptography.serialization.load_der_private_key(der: bytes, password: bytes) -> EllipticCurvePrivateKey
    ```
- ### **cryptography.x509**:
    **_SUPPORTED CERTIFICATE: signed using ECDSA with SHA256_**
    ```python
    cryptography.x509.load_der_x509_certificate(der: bytes) -> Certificate
    ```
