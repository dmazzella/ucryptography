# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import hashes


def main():
    expected_sha1 = b'D\x00l\xff\xcc\xd5y\x033\xef\xadM05r3\x17\x88r&'
    expected_sha256 = b"\x1a\xa4\x08\xe4\xe4\xeb\x99D\xb8B\xf97!\x80\x88\xff\x17\x1e\xa0~\x1f\xb9\xbeL\x1a\x94b\xa7\xef\t{\x9a"
    expected_sha384 = b"\xacX\xbeE\x15\xf3\xd6\x84\xac\xa2\x0f\xffY\x91\x03\xbb\xa2\xd7\xc5\x89Z\xfd\x18]\xc6\x1f\x0c\xa7\x13\xcf\xc4\x06Ky2=Auz_r\xe0\x02\x80\xba!O\xd6"
    expected_sha512 = b"\x10\xa7\xc8\xfa\xefygw\xe3\x86/\x19NWt/b\xf9\x8f\xb4##\x9fR\x13\xd2\xc6y\xb2\x17Z-`\x81\xa47\x04\xdc\x07\\\xbd\x8e!\x94\xc0\x94 l\x07w\xb0\xed\x87,V\xa5\x00\xb3\xdc\xd2\x00\xe9k<"

    digest = hashes.Hash(hashes.SHA1())
    digest.update(b"caccone" * 1000)
    print(expected_sha1 == digest.finalize())

    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"caccone" * 1000)
    print(expected_sha256 == digest.finalize())

    digest = hashes.Hash(hashes.SHA384())
    digest.update(b"caccone" * 1000)
    print(expected_sha384 == digest.finalize())

    digest = hashes.Hash(hashes.SHA512())
    digest.update(b"caccone" * 1000)
    print(expected_sha512 == digest.finalize())


if __name__ == "__main__":
    main()
