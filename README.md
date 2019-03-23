# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto/)
---------------

## Classes
- ### **EllipticCurve**:
    - name -> **str**
        - _"secp256r1"_
    - ~~key_size -> **int**~~
        - ~~_256_~~

- ### **EllipticCurvePublicNumbers**:
    - curve -> **EllipticCurve**
    - x -> **int**
    - y -> **int**

- ### **EllipticCurvePrivateNumbers**:
    - public_numbers -> **EllipticCurvePublicNumbers**
    - private_value -> **int**

- ### **EllipticCurvePublicKey**:
    - public_numbers -> **EllipticCurvePublicNumbers**
    - ~~public_bytes -> **bytes**~~
    - verify(signature:**tuple**(r:**int**, s:**int**), digest: **bytes**, ~~signature_algorithm:**bytes**~~) -> ~~raise: **InvalidSignature**~~ **bool**
    - ~~key_size -> **int**~~
        - ~~_256_~~

- ### **EllipticCurvePrivateKey**:
    - ~~curve -> **EllipticCurve**~~
    - private_numbers -> **EllipticCurvePrivateNumbers**
    - ~~private_bytes -> **bytes**~~
    - sign(digest: **bytes**, ~~signature_algorithm:**bytes**~~) -> ~~**bytes**~~ **tuple**(r:**int**, s:**int**)
    - ~~key_size -> **int**~~
        - ~~_256_~~

- ~~**HashAlgorithm**:~~
    - ~~name -> **str**~~
        - ~~_"sha256"_~~

- ### **Certificate**:
    - version -> **str**
    - serial_number -> **int**
    - public_key -> **EllipticCurvePublicKey**
    - not_valid_before -> **str**
    - not_valid_after -> **str**
    - issuer -> **dict**
    - subject -> **dict**
    - signature_algorithm_oid -> **str**
    - ~~signature_hash_algorithm -> **HashAlgorithm**~~
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
    ```python
    cryptography.x509.load_der_x509_certificate(der: bytes) -> Certificate
    ```
