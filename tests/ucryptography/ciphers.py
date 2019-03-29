# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import ciphers
import sys
if sys.platform == 'pyboard':
    from uos import urandom
elif sys.platform == 'linux':
    def urandom(size):
        with open("/dev/urandom", "rb") as f:
            return f.read(size)
else:
    import urandom as random
    def urandom(size):
        try:
            return bytes(random.getrandbits(8) for i in range(size))
        except ImportError as exc:
            raise exc


def main():
    data = b"a secret message"
    aad = b"authenticated but unencrypted data"
    key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
    nonce = b'7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0'

    # key = ciphers.AESGCM.generate_key(256)
    # nonce = urandom(12)

    aesgcm = ciphers.AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, aad)
    print(ct)
    dt = aesgcm.decrypt(nonce, ct, aad)
    print(dt)


if __name__ == "__main__":
    main()
