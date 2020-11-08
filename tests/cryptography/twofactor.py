# -*- coding: utf-8 -*-
import os
import random
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives import hashes


def hotp(key, length, algorithm, counter):
    hotp = HOTP(key, length, algorithm, backend=default_backend())
    hotp_value = hotp.generate(counter)
    hotp.verify(hotp_value, counter)
    print("HOTP", hotp_value)


def totp(key, length, algorithm, time):
    totp = TOTP(key, length, algorithm, 30, backend=default_backend())
    totp_value = totp.generate(time)
    totp.verify(totp_value, time)
    print("TOTP", totp_value)


if __name__ == "__main__":
    # key = os.urandom(20)
    key = b'G\xc6\xbe\x06\x83\xf6 g\xcb\xe19\n\x11\x12r\x94-\xa4*\x81'
    # counter = random.randint(0, 1000)
    counter = 0
    print("key:", key)
    print("counter:", counter)
    hotp(key, 6, hashes.SHA1(), counter)
    hotp(key, 6, hashes.SHA256(), counter)
    hotp(key, 6, hashes.SHA512(), counter)

    # t = time.time()
    t = 1604858403
    print("time:", t)
    totp(key, 6, hashes.SHA1(), t)
    totp(key, 6, hashes.SHA256(), t)
    totp(key, 6, hashes.SHA512(), t)
