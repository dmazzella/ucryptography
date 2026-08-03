# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
try:
    from cryptography import twofactor

    HOTP = twofactor.HOTP
    TOTP = twofactor.TOTP
    from cryptography import hashes
except ImportError:
    from cryptography.hazmat.primitives.twofactor.hotp import HOTP
    from cryptography.hazmat.primitives.twofactor.totp import TOTP
    from cryptography.hazmat.primitives import hashes


def _assert_rejected(label, fn):
    try:
        fn()
    except Exception as ex:
        print("  reject OK:", label, "->", type(ex).__name__)
        return
    raise AssertionError("SECURITY: wrong OTP accepted -> " + label)


def hotp(key, length, algorithm, counter):
    hotp = HOTP(key, length, algorithm)
    hotp_value = hotp.generate(counter)
    hotp.verify(hotp_value, counter)
    # A one-time password computed for one counter must not verify against a
    # different counter (guards against verify() being a no-op / fail-open).
    wrong_counter = counter + 1
    while HOTP(key, length, algorithm).generate(wrong_counter) == hotp_value:
        wrong_counter += 1
    _assert_rejected(
        "HOTP wrong counter",
        lambda: HOTP(key, length, algorithm).verify(hotp_value, wrong_counter),
    )
    print("HOTP", hotp_value)


def totp(key, length, algorithm, time):
    totp = TOTP(key, length, algorithm, 30)
    totp_value = totp.generate(time)
    totp.verify(totp_value, time)
    # A TOTP from one time window must not verify in a far-away window.
    wrong_time = time + 3000
    while TOTP(key, length, algorithm, 30).generate(wrong_time) == totp_value:
        wrong_time += 30
    _assert_rejected(
        "TOTP wrong time window",
        lambda: TOTP(key, length, algorithm, 30).verify(totp_value, wrong_time),
    )
    print("TOTP", totp_value)


if __name__ == "__main__":
    # key = uos.urandom(20)
    key = b"G\xc6\xbe\x06\x83\xf6 g\xcb\xe19\n\x11\x12r\x94-\xa4*\x81"
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
