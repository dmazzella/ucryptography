# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def main():
    data = b"a secret message"
    def AES_GCM():
        aad = b'\xDE\xAD\xBE\xEF'
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = b'7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0'
        # key = AESGCM.generate_key(256)
        # nonce = os.urandom(12)

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, aad)
        print(ct)
        dt = aesgcm.decrypt(nonce, ct, aad)
        print(dt)

    print("AESGCM")
    AES_GCM()

    def GCM():
        aad = b'\xDE\xAD\xBE\xEF'
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = iv = b'7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0'
        # key = ciphers.AESGCM.generate_key(256)
        # nonce = iv = urandom(12)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        print(ct + tag)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag=tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)
        
    print("AES GCM")
    GCM()

    def CBC():
        key = b'g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b'
        iv = b'W/\xa9M\xe4\xa2\x87\xe8\xc0Z\x96D\xd2\xb8\xdd\xc3'
        # key = os.urandom(32)
        # iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
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
