# -*- coding: utf-8 -*-
# pylint: disable=import-error
from ubinascii import a2b_base64
from uio import BytesIO
from cryptography import serialization

def loadf_sequence(f):
    f.seek(f.read().index(b'-----BEGIN') or 0)
    l = f.readline()
    if not l.startswith(b'-----BEGIN'):
        # not a pem
        f.seek(0)
        data = f.read()
        if data.startswith(b'\x30'):
            return data
        return a2b_base64(data)

    # pem
    lines = []
    while 1:
        l = f.readline()
        if l == b'' or l.startswith(b'-----END'):
            break
        lines.append(l)
    return a2b_base64(b''.join(lines).replace(b'\n', b''))


def load_sequence(filename):
    f = open(filename, 'rb')
    try:
        return loadf_sequence(f)
    finally:
        f.close()

def loads_sequence(s):
    f = BytesIO(bytes(s, 'utf-8'))
    try:
        return loadf_sequence(f)
    finally:
        f.close()

PRIVATE_KEY_DER = loads_sequence('''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEKi+GleZpNE2E+oHgtnSkvTfAQ8zGhM+OHjqo74DM0RoAoGCCqGSM49
AwEHoUQDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuOORNL6DeWlqbnKMK1l7xf3wNe
1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END EC PRIVATE KEY-----''')

def main():
    private_key = serialization.load_der_private_key(PRIVATE_KEY_DER, None)
    print("load_der_private_key: ", private_key)

if __name__ == "__main__":
    main()