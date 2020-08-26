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
        bdev = utils.CipheredBlockDevice(128, erase_block_size=512, algorithm=None)
        uos.VfsLfs2.mkfs(bdev)
        uos.mount(uos.VfsLfs2(bdev), "/cachefs")
    except OSError as ex:
        print("error mounting /cachefs", ex)
    else:
        data = b"\xaa" * 250

        dump_bytes("/cachefs/test0.data", data)
        print(uos.stat("/cachefs/test0.data"))
        assert load_bytes("/cachefs/test0.data") == data
        uos.remove("/cachefs/test0.data")
        print(uos.statvfs("/cachefs"))
        uos.mkdir("/cachefs/test0.dir")
        uos.rmdir("/cachefs/test0.dir")

except OSError as ex:
    print(ex)
