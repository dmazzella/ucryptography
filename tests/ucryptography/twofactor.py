# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import uos
import utime
import urandom

from cryptography import twofactor
from cryptography import hashes, hmac


def hotp(key, length, algorithm, counter):
    hotp = twofactor.HOTP(key, length, algorithm)
    hotp_value = hotp.generate(counter)
    hotp_value = "{0:0{1}}".format(hotp_value, length).encode()
    hotp.verify(int(hotp_value), counter)
    print("HOTP", hotp_value)


def totp(key, length, algorithm, time):
    totp = twofactor.TOTP(key, length, algorithm, 30)
    totp_value = totp.generate(time)
    totp_value = "{0:0{1}}".format(totp_value, length).encode()
    totp.verify(int(totp_value), time)
    print("TOTP", totp_value)


if __name__ == "__main__":
    # key = uos.urandom(20)
    key = b'G\xc6\xbe\x06\x83\xf6 g\xcb\xe19\n\x11\x12r\x94-\xa4*\x81'
    # counter = urandom.randint(0, 1000)
    counter = 0
    print("key:", key)
    print("counter:", counter)
    hotp(key, 6, hashes.SHA1(), counter)
    hotp(key, 6, hashes.SHA256(), counter)
    hotp(key, 6, hashes.SHA512(), counter)

    # t = utime.time()
    t = 1604858403
    print("time:", t)
    totp(key, 6, hashes.SHA1(), t)
    totp(key, 6, hashes.SHA256(), t)
    totp(key, 6, hashes.SHA512(), t)
