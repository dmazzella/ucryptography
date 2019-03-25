# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
from ubinascii import a2b_base64
from cryptography import serialization
try:
    from util import loads_sequence
except ImportError:
    from ucryptography.util import loads_sequence

PRIVATE_KEY_DER = loads_sequence('''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEKi+GleZpNE2E+oHgtnSkvTfAQ8zGhM+OHjqo74DM0RoAoGCCqGSM49
AwEHoUQDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuOORNL6DeWlqbnKMK1l7xf3wNe
1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END EC PRIVATE KEY-----''')


def main():
    private_key = serialization.load_der_private_key(PRIVATE_KEY_DER, None)
    print("load_der_private_key:", private_key)

    print("private_bytes", private_key.private_bytes())

    private_numbers = private_key.private_numbers()
    print("private_numbers.private_value: ", private_numbers.private_value)

    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    print("public_key.curve", public_key.curve.name)
    print("public_key.public_bytes", public_key.public_bytes())
    print("public_key.public_numbers.x", public_numbers.x)
    print("public_key.public_numbers.y", public_numbers.y)


if __name__ == "__main__":
    main()
