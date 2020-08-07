# ucryptography

Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)
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
    - p -> **int**
        - _0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff_
    - a -> **int**
        - _-0x3_
    - b -> **int**
        - _0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_
    - n -> **int**
        - _0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_
    - G_x -> **int**
        - _0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_
    - G_y -> **int**
        - _0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_

- ### **cryptography.ec.SECP521R1**:
    - name -> **str**
        - _"secp521r1"_
    - key_size -> **int**
        - _521_
    - p -> **int**
        - _0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_
    - a -> **int**
        - _-0x3_
    - b -> **int**
        - _0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00_
    - n -> **int**
        - _0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409_
    - G_x -> **int**
        - _0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66_
    - G_y -> **int**
        - _0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650_


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
    - exchange([algorithm:cryptography.ec.ECDH], peer_public_key:**cryptography.ec.EllipticCurvePublicKey**) -> **bytes**
    - public_key() -> **cryptography.ec.EllipticCurvePublicKey**
    - private_numbers() -> **cryptography.ec.EllipticCurvePrivateNumbers**
    - private_bytes() -> **bytes**
    - sign(digest: **bytes**) -> **bytes**
    - key_size -> **int**
        - _256_

- ### **cryptography.hashes.SHA256**:
    - name -> **str**
        - _"sha256"_
    - digest_size -> **int**
        - _32_

- ### **cryptography.hashes.Hash**:
    - algorithm -> **cryptography.hashes.SHA256**
    - update(data: **bytes**)
    - copy() -> **cryptography.hashes.Hash**
    - finalize() -> **bytes**

- ### **cryptography.hmac.HMAC**:
    - update(data: **bytes**)
    - copy() -> **cryptography.hmac.HMAC**
    - verify(data: **bytes**) -> raise: **InvalidSignature**
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

- ### **cryptography.ciphers.AESGCM**:
    - generate_key(bit_length: **int**) -> **bytes**
    - encrypt(nonce: **bytes**, plain_text_data: **bytes**, aad: **bytes** or **None**) -> **bytes**
    - decrypt(nonce: **bytes**, encrypted_data: **bytes**, aad: **bytes** or **None**) -> **bytes**

- ### **cryptography.ciphers.algorithms.AES(key: **bytes**)**

- ### **cryptography.ciphers.modes.CBC(initialization_vector: **bytes**)**

- ### **cryptography.ciphers.modes.GCM(initialization_vector: **bytes**, tag=**None**|**bytes**, min_tag_length=**16**)**

- ### **cryptography.ciphers.Cipher.encryptor**:
    - update(data: **bytes**) -> **bytes**
    - finalize() -> **bytes**
    - authenticate_additional_data(data: **bytes**) -> None
        - only for **cryptography.ciphers.modes.GCM**
    - tag -> **bytes**
        - only for **cryptography.ciphers.modes.GCM**

- ### **cryptography.ciphers.Cipher.decryptor**:
    - update(data: **bytes**) -> **bytes**
    - finalize() -> **bytes**
    - authenticate_additional_data(data: **bytes**) -> None
        - only for **cryptography.ciphers.modes.GCM**

- ### **cryptography.ciphers.Cipher**:
    - encryptor() -> **cryptography.ciphers.Cipher.encryptor**
    - decryptor() -> **cryptography.ciphers.Cipher.decryptor**

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
- ### **cryptography.hmac**:
    ```python
    cryptography.hmac.HMAC(key: bytes, hash_algorithm: cryptography.hashes.SHA256()) -> HMAC
    ```
- ### **cryptography.ciphers**:
    ```python
    cryptography.ciphers.AESGCM(key: cryptography.ciphers.AESGCM.generate_key(256)) -> AESGCM
    cryptography.ciphers.Cipher(cryptography.ciphers.algorithms.AES(key: bytes), cryptography.ciphers.modes.CBC(iv: bytes)) -> Cipher
    cryptography.ciphers.Cipher(cryptography.ciphers.algorithms.AES(key: bytes), cryptography.ciphers.modes.GCM(iv: bytes)) -> Cipher
    ```
- ### **cryptography.ec**:
    ```python
    cryptography.ec.generate_private_key(curve: cryptography.ec.SECP256R1()) -> EllipticCurvePrivateKey
    cryptography.ec.derive_private_key(private_value: int, curve: cryptography.ec.SECP256R1()) -> EllipticCurvePrivateKey
    ```
