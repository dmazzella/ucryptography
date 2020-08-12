# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


def main():
    expected_sha256 = b'\x80\x1c\x18\n\xc0\xc9W=p\xcan\x1a\x0f\xb6\n\x0b\xe9\x8d\xdf\xb3\xc3\xe6\xea+\x8b\xa9:Na4\xd8\x9c'
    expected_sha384 = b"\xc3\x01O;\xc7a\x86\xbc\xa8v\x05Vt\x95\x83W\xaa\x16\xfc\xc9\xf7\xa6~S\x85\xed\xb4-\xc6t\xb2.\xdf^\xdee\x17\xda\x1a\xed\x168\xa7:SD\xf1'"
    expected_sha512 = b'\xdf\xe9\x07\xe6\xf5\x10r\xcf\x9bM*J\xf8\xe3\xf7\xa4\xd3O6z\x1d\x03\xa6\xce\xbd\xe1\x0f\x8b\xb1/O\xdb\xdd-M\xe0b\xaar\x87\xc4\xeaW\x91\x8e\x8b\xd5\x8c\x8e\xe5\xd86\xb0\x81;\xe1RaL\xdd\xbf)\x12D'
    key = b'\x93\x8dYL%\xd7;dV\x94D+$\x86\x12gD\xe6\x99x\xdf2\x82\x08Y\x05\xb5m\x8d}\x15}'

    hmac_context = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_context.update(b"caccone"*1000)
    print(expected_sha256 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.SHA384(), backend=default_backend())
    hmac_context.update(b"caccone"*1000)
    print(expected_sha384 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    hmac_context.update(b"caccone"*1000)
    print(expected_sha512 == hmac_context.finalize())


if __name__ == "__main__":
    main()
