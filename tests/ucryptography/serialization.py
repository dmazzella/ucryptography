# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import serialization, hashes
try:
    from util import loads_sequence
except ImportError:
    from ucryptography.util import loads_sequence

PRIVATE_KEY_DER = loads_sequence('''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEKi+GleZpNE2E+oHgtnSkvTfAQ8zGhM+OHjqo74DM0RoAoGCCqGSM49
AwEHoUQDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuOORNL6DeWlqbnKMK1l7xf3wNe
1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END EC PRIVATE KEY-----''')


PUBLIC_KEY_DER = loads_sequence('''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuO
ORNL6DeWlqbnKMK1l7xf3wNe1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END PUBLIC KEY-----''')

def main():
    private_key = serialization.load_der_private_key(PRIVATE_KEY_DER, None)
    print("curve", private_key.curve.name)
    print("key_size", private_key.key_size)

    print("private_bytes", private_key.private_bytes())
    print("private_bytes DER", private_key.private_bytes(serialization.Encoding.DER))
    print("private_bytes PEM", private_key.private_bytes(serialization.Encoding.PEM))

    private_numbers = private_key.private_numbers()
    print("private_numbers.private_value: ", private_numbers.private_value)

    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    print("public_key.curve", public_key.curve.name)
    public_bytes = public_key.public_bytes()
    print("public_key.public_bytes", public_bytes)
    print("public_key.public_numbers.x", public_numbers.x)
    print("public_key.public_numbers.y", public_numbers.y)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    msg_hash = digest.finalize()
    signature = private_key.sign(msg_hash)
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)
    public_key.verify(signature, msg_hash)

    public_key1 = serialization.load_der_public_key(PUBLIC_KEY_DER)
    public_numbers1 = public_key1.public_numbers()
    print("public_key.curve", public_key1.curve.name)
    public_bytes1 = public_key1.public_bytes()
    print("public_key.public_bytes", public_bytes1)
    print("public_key.public_numbers.x", public_numbers1.x)
    print("public_key.public_numbers.y", public_numbers1.y)
    public_key1.verify(signature, msg_hash)


if __name__ == "__main__":
    main()
