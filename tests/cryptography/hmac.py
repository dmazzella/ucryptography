# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


def main():
    expected = b'\x80\x1c\x18\n\xc0\xc9W=p\xcan\x1a\x0f\xb6\n\x0b\xe9\x8d\xdf\xb3\xc3\xe6\xea+\x8b\xa9:Na4\xd8\x9c'
    key = b'\x93\x8dYL%\xd7;dV\x94D+$\x86\x12gD\xe6\x99x\xdf2\x82\x08Y\x05\xb5m\x8d}\x15}'
    algorithm = hashes.SHA256()
    hmac_context = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_context.update(b"caccone"*1000)
    print(expected == hmac_context.finalize())


if __name__ == "__main__":
    main()
