# -*- coding: utf-8 -*-
# pylint:disable=import-error
# pylint:disable=no-member
import uos
import urandom
import utime

from cryptography import ciphers
from cryptography import utils


def profile(f, *args, **kwargs):
    def profiled_func(*args, **kwargs):
        t = utime.ticks_us()
        r = f(*args, **kwargs)
        dt = utime.ticks_diff(utime.ticks_us(), t)
        print("{!r} => {:6.3f}".format(f, dt / 1000))
        return r

    return profiled_func


@profile
def dump_bytes(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


@profile
def load_bytes(filename):
    with open(filename, "rb") as f:
        return f.read()


if __name__ == "__main__":
    try:
        try:
            key = b"g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b"
            iv = b"W/\xa9M\xe4\xa2\x87\xe8\xc0Z\x96D\xd2\xb8\xdd\xc3"

            cipher = ciphers.Cipher(
                ciphers.algorithms.AES(key),
                ciphers.modes.CBC(iv)
            )
            bdev = utils.CipheredBlockDevice(
                128,
                erase_block_size=512,
                cipher=cipher
            )
            uos.VfsLfs2.mkfs(bdev)
            uos.mount(uos.VfsLfs2(bdev), "/flash2")
        except OSError as ex:
            print("error mounting /flash2", ex)
        else:
            for i in range(1):
                data = b"\xaa" * urandom.randint(0, 1024)
                fname = "/flash2/test{}.data".format(i)
                dump_bytes(fname, data)
                print(uos.stat(fname))
                assert load_bytes(fname) == data
                print(uos.statvfs("/flash2"))

    except OSError as ex:
        print(ex)
