# ucryptography

<b><i>Lightweight porting of [cryptography](https://github.com/pyca/cryptography)  to Micropython based on [ARM Mbed TLS](https://github.com/ARMmbed/mbedtls)</i></b>

> [!TIP]
> If you find **ucryptography** useful, consider :star: this project
> and why not ... [Buy me a coffee](https://www.buymeacoffee.com/damianomazp) :smile:

## Basic usage

```python
try:
    from cryptography import hashes, rsa, padding
except ImportError:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import padding

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

<details><summary><b>UNIX port (standard)</b></summary>
<p>

```bash
$ git clone https://github.com/micropython/micropython.git
$ cd micropython
micropython$ git submodule update --init --depth 1
micropython$ git clone https://github.com/dmazzella/ucryptography.git usercmodule/ucryptography
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -j2 -C ports/unix/ VARIANT="standard" MICROPY_SSL_AXTLS=0 MICROPY_SSL_MBEDTLS=1 USER_C_MODULES="$(pwd)/usercmodule"
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
micropython$ cd usercmodule/ucryptography
ucryptography$ git submodule update --init --depth 1
ucryptography$ cd ../../
micropython$ make -j2 -C mpy-cross/
micropython$ make -C ports/stm32 BOARD=ARDUINO_PORTENTA_H7 USER_C_MODULES="$(pwd)/usercmodule"
```
</p>
</details>

<details><summary><b>Feature toggles (optional)</b></summary>
<p>

Every ucryptography feature is compiled in by default. Each is guarded by a
`MICROPY_PY_UCRYPTOGRAPHY_*` flag (all default `1`) declared in
`modcryptography_features.h`. Set a flag to `0` to compile the feature out: its
type stays registered (no `AttributeError`) but constructing it raises
`NotImplementedError` naming the flag to re-enable.

Override a flag either by editing `modcryptography_features.h`, or — on the
make-based ports (unix, stm32) — by passing `-D<FLAG>=0` through `CFLAGS_EXTRA`:

```bash
micropython$ make -j2 -C ports/unix/ VARIANT="standard" MICROPY_SSL_AXTLS=0 MICROPY_SSL_MBEDTLS=1 \
    CFLAGS_EXTRA="-DMICROPY_PY_UCRYPTOGRAPHY_TRIPLEDES=0 -DMICROPY_PY_UCRYPTOGRAPHY_OAEP=0 -DMICROPY_PY_UCRYPTOGRAPHY_PSS=0" \
    USER_C_MODULES="$(pwd)/usercmodule"
```

Flags (prefix `MICROPY_PY_UCRYPTOGRAPHY_`, all default `1`):

| Flag suffix | Python API disabled when `0` |
|---|---|
| `SHA1` / `SHA256` / `SHA384` / `SHA512` | `hashes.SHA1` … `hashes.SHA512` |
| `BLAKE2S` | `hashes.BLAKE2s` |
| `HASH` | `hashes.Hash` |
| `HMAC` | `hmac.HMAC` |
| `AES` | `ciphers.algorithms.AES` |
| `AESGCM` | `ciphers.AESGCM` |
| `TRIPLEDES` | `ciphers.algorithms.TripleDES` |
| `PKCS1V15` | `padding.PKCS1v15` |
| `MGF1` | `padding.MGF1` |
| `OAEP` | `padding.OAEP` |
| `PSS` | `padding.PSS` |
| `RSA` | `rsa.*` (keys, sign, verify) |
| `EC` | `ec.*` (keys, ECDH, ECDSA) |
| `ED25519` | `ed25519.*` |
| `X509` | `x509` reading (`load_*`, `Certificate`) |
| `X509_CREATE` | `x509.CertificateBuilder` |
| `X509_CSR` | `x509` CSR read/write (`load_*_x509_csr`, `CertificateSigningRequestBuilder`) |
| `TWOFACTOR` | `twofactor.HOTP` / `twofactor.TOTP` |

Dependencies are enforced automatically: `MGF1=0` also disables `OAEP` and `PSS`;
`X509=0` also disables `X509_CREATE` and `X509_CSR`. The CSR builder additionally
needs `X509_CREATE` (they share the mbedtls certificate-writing stack).

Most toggles only stub the Python API — the underlying mbedtls primitive stays
because the port's TLS stack shares it. A few settings additionally shrink the
mbedtls library (they gate modules exclusive to ucryptography): `TRIPLEDES=0`
drops `MBEDTLS_DES_C`; `OAEP=0` **and** `PSS=0` drop `MBEDTLS_PKCS1_V21`;
`X509_CREATE=0` drops `MBEDTLS_X509_CREATE_C` + `MBEDTLS_X509_CRT_WRITE_C`;
`X509_CSR=0` drops `MBEDTLS_X509_CSR_PARSE_C` + `MBEDTLS_X509_CSR_WRITE_C`.

CSR read note: mbedtls natively parses only KeyUsage and SubjectAlternativeName
from a CSR; BasicConstraints and ExtendedKeyUsage are recovered from the raw
request, and any other requested extension is exposed as an
`UnrecognizedExtension`. A requested BasicConstraints/ExtendedKeyUsage marked
*critical* is rejected by mbedtls, so keep those non-critical in a CSR.

</p>
</details>


## Goals 

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
  - [x] load_pem_public_key
  - [x] load_pem_private_key
  - [x] NoEncryption
  - [x] BestAvailableEncryption
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
  - [x] load_pem_x509_certificate
  - [x] random_serial_number
  - [x] Certificate
  - [x] CertificateBuilder
  - [x] Name
  - [x] NameAttribute
  - [x] ObjectIdentifier
  - [x] NameOID
  - [x] SubjectAlternativeName
  - [x] DNSName
  - [x] IPAddress
  - [x] BasicConstraints
  - [x] KeyUsage
  - [x] ExtendedKeyUsage
  - [x] ExtendedKeyUsageOID
  - [x] SubjectKeyIdentifier
  - [x] AuthorityKeyIdentifier
  - [x] UnrecognizedExtension
  - [x] load_der_x509_csr
  - [x] load_pem_x509_csr
  - [x] CertificateSigningRequest
  - [x] CertificateSigningRequestBuilder
