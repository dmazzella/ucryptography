# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import random

try:
    from cryptography import ciphers

    Cipher = ciphers.Cipher
    algorithms = ciphers.algorithms
    modes = ciphers.modes
    AESGCM = ciphers.AESGCM
except ImportError:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def urandom(size):
    try:
        return bytes(random.getrandbits(8) for i in range(size))
    except ImportError as exc:
        raise exc


def main():
    data = b"a secret message"

    def AES_AESGCM():
        aad = b"\xDE\xAD\xBE\xEF"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"
        # key = AESGCM.generate_key(256)
        # nonce = urandom(12)

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, aad)
        print(ct)
        dt = aesgcm.decrypt(nonce, ct, aad)
        print(dt)

    print("AESGCM")
    AES_AESGCM()

    def AES_GCM():
        aad = b"\xDE\xAD\xBE\xEF"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = iv = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"
        # key = AESGCM.generate_key(256)
        # nonce = iv = urandom(12)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        print(ct + tag)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag=tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES GCM")
    AES_GCM()

    def AES_CBC():
        key = b"g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b"
        iv = b"W/\xa9M\xe4\xa2\x87\xe8\xc0Z\x96D\xd2\xb8\xdd\xc3"
        # key = urandom(32)
        # iv = urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES CBC")
    AES_CBC()

    def AES_ECB():
        key = b"g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b"
        # key = urandom(32)

        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES ECB")
    AES_ECB()

    def TripleDES_CBC():
        key = b"\xc6\xcf\x90\xb2s\xca\x94\x15]-aDZ\x8b\xe9jT\x068\xec\x9ddi\x9d"
        iv = b"\xf4\xe4l\xd9\x10e\xb3Z"
        # key = urandom(24)
        # iv = urandom(8)

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("3DES CBC")
    TripleDES_CBC()

    def TripleDES_ECB():
        key = b"\xc6\xcf\x90\xb2s\xca\x94\x15]-aDZ\x8b\xe9jT\x068\xec\x9ddi\x9d"
        # key = urandom(24)

        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("3DES ECB")
    TripleDES_ECB()


if __name__ == "__main__":
    main()
