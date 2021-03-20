# -*- coding: utf-8 -*-
# pylint:disable=import-error
# pylint:disable=no-member
HAS_STORAGE = False
try:
    import pyb
    HAS_STORAGE = hasattr(pyb, 'Flash')
except ImportError:
    pass

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
            BLOCK_SIZE = 1024
            if HAS_STORAGE:
                uos.umount("/flash")
                FS_SIZE = BLOCK_SIZE * (256-64)
                bdev1 = pyb.Flash(start=0, len=FS_SIZE)
                bdev2 = pyb.Flash(start=FS_SIZE, len=(BLOCK_SIZE * 64))
                bdevc1 = utils.CipheredBlockDevice(
                    storage=bdev1,
                    blocks=128,
                    erase_block_size=BLOCK_SIZE,
                    cipher=cipher
                )
                bdevc2 = utils.CipheredBlockDevice(
                    storage=bdev2,
                    blocks=128,
                    erase_block_size=BLOCK_SIZE,
                    cipher=cipher
                )

                uos.VfsFat.mkfs(bdevc1)
                uos.mount(uos.VfsFat(bdevc1), "/flash")
                print(uos.statvfs("/flash"))
            else:
                bdev = utils.CipheredBlockDevice(
                    blocks=128,
                    erase_block_size=BLOCK_SIZE,
                    cipher=cipher
                )
            uos.VfsLfs2.mkfs(bdevc2)
            uos.mount(uos.VfsLfs2(bdevc2), "/flash2")
            print(uos.statvfs("/flash2"))
        except OSError as ex:
            print("os error", ex)
        else:
            for i in range(10):
                data = b"\xaa" * urandom.randint(0, 1024)
                fname = "/flash2/test{}.data".format(i)
                dump_bytes(fname, data)
                print(uos.stat(fname))
                assert load_bytes(fname) == data
                # print(data)
                print(uos.statvfs("/flash2"))

    except OSError as ex:
        print(ex)
