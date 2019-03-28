# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto/)
---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

```python
import cryptography
```

## Exceptions
- ### **cryptography.exceptions.InvalidSignature**
- ### **cryptography.exceptions.AlreadyFinalized**
- ### **cryptography.exceptions.UnsupportedAlgorithm**
- ### **cryptography.exceptions.InvalidKey**

## Classes
- ### **cryptography.ec.SECP256R1**:
    - name -> **str**
        - _"secp256r1"_
    - key_size -> **int**
        - _256_

- ### **cryptography.ec.EllipticCurvePublicNumbers**:
    - curve -> **cryptography.ec.SECP256R1**
    - x -> **int**
    - y -> **int**
    - public_key() -> **cryptography.ec.EllipticCurvePublicKey**

- ### **cryptography.ec.EllipticCurvePrivateNumbers**:
    - public_numbers() -> **cryptography.ec.EllipticCurvePublicNumbers**
    - private_value -> **int**
    - private_key() -> **cryptography.ec.EllipticCurvePrivateKey**

- ### **cryptography.ec.EllipticCurvePublicKey**:
    - public_numbers() -> **cryptography.ec.EllipticCurvePublicNumbers**
    - public_bytes() -> **bytes**
    - verify(signature:**bytes**, digest: **bytes**) -> raise: **InvalidSignature**
    - key_size -> **int**
        - _256_

- ### **cryptography.ec.EllipticCurvePrivateKey**:
    - curve -> **cryptography.ec.SECP256R1**
    - public_key() -> **cryptography.ec.EllipticCurvePublicKey**
    - private_numbers() -> **cryptography.ec.EllipticCurvePrivateNumbers**
    - private_bytes() -> **bytes**
    - sign(digest: **bytes**) -> **bytes**
    - key_size -> **int**
        - _256_

- ### **cryptography.hashes.SHA256**:
    - name -> **str**
        - _"sha256"_
    - key_size -> **int**
        - _256_

- ### **cryptography.hashes.Hash**:
    - algorithm -> **cryptography.hashes.SHA256**
    - update(data: **bytes**)
    - copy() -> **cryptography.hashes.Hash**
    - finalize() -> **bytes**

- ### **cryptography.x509.Certificate**:
    - version -> **int**
    - serial_number -> **int**
    - public_key() -> **cryptography.ec.EllipticCurvePublicKey**
    - not_valid_before -> **str**
    - not_valid_after -> **str**
    - issuer -> **dict**
    - subject -> **dict**
    - signature_algorithm_oid -> **dict**
    - signature_hash_algorithm -> **cryptography.ec.SHA256**
    - ~~fingerprint -> **bytes**~~
    - extensions -> **dict**
    - signature -> **bytes**
    - tbs_certificate_bytes -> **bytes**
    - public_bytes() -> **bytes**

## Methods

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
- ### **cryptography.hashes**:
    ```python
    cryptography.hashes.Hash(hash_algorithm: cryptography.hashes.SHA256()) -> Hash
    ```