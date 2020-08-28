# -*- coding: utf-8 -*-
# pylint:disable=import-error
# pylint:disable=no-member
import uos
import utime

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


try:
    try:
        bdev = utils.CipheredBlockDevice(128)
        uos.VfsLfs2.mkfs(bdev)
        uos.mount(uos.VfsLfs2(bdev), "/flash2")
    except OSError as ex:
        print("error mounting /flash2", ex)
    else:
        data = b"\xaa" * 250

        dump_bytes("/flash2/test0.data", data)
        print(uos.stat("/flash2/test0.data"))
        assert load_bytes("/flash2/test0.data") == data
        print(uos.statvfs("/flash2"))

except OSError as ex:
    print(ex)
