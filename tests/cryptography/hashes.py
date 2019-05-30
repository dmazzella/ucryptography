# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def main():
    expected = b'\x1a\xa4\x08\xe4\xe4\xeb\x99D\xb8B\xf97!\x80\x88\xff\x17\x1e\xa0~\x1f\xb9\xbeL\x1a\x94b\xa7\xef\t{\x9a'
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(b"caccone"*1000)
    print(expected == digest.finalize())


if __name__ == "__main__":
    main()
