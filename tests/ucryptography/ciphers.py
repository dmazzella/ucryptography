# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import sys

from cryptography import ciphers

import utime

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


def profile(f, *args, **kwargs):

    def new_func(*args, **kwargs):
        t = utime.ticks_us()
        result = f(*args, **kwargs)
        delta_t = utime.ticks_diff(utime.ticks_us(), t)
        print('{!s}({:6.3f})'.format(f, delta_t/1000))
        return result
    return new_func


def main():
    data = b"a secret message"

    @profile
    def AES_GCM():
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

    print("AESGCM")
    AES_GCM()

    @profile
    def GCM():
        aad = b"authenticated but unencrypted data"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = iv = b'7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0'
        # key = ciphers.AESGCM.generate_key(256)
        # nonce = iv = urandom(12)

        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key), ciphers.modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        print(ct + tag)
        cipher = ciphers.Cipher(ciphers.algorithms.AES(
            key), ciphers.modes.GCM(iv, tag=tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES GCM")
    GCM()

    @profile
    def CBC():
        key = b'g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b'
        iv = b'W/\xa9M\xe4\xa2\x87\xe8\xc0Z\x96D\xd2\xb8\xdd\xc3'
        # key = os.urandom(32)
        # iv = os.urandom(16)

        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key), ciphers.modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES CBC")
    CBC()


if __name__ == "__main__":
    main()
