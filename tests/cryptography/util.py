# -*- coding: utf-8 -*-
# pylint: disable=import-error
from binascii import a2b_base64
from io import BytesIO


def loadf_sequence(f):
    f.seek(f.read().index(b"-----BEGIN") or 0)
    l = f.readline()
    if not l.startswith(b"-----BEGIN"):
        # not a pem
        f.seek(0)
        data = f.read()
        if data.startswith(b"\x30"):
            return data
        return a2b_base64(data)

    # pem
    lines = []
    while 1:
        l = f.readline()
        if l == b"" or l.startswith(b"-----END"):
            break
        lines.append(l)
    return a2b_base64(b"".join(lines).replace(b"\n", b""))


def load_sequence(filename):
    f = open(filename, "rb")
    try:
        return loadf_sequence(f)
    finally:
        f.close()


def loads_sequence(s):
    f = BytesIO(bytes(s, "utf-8"))
    try:
        return loadf_sequence(f)
    finally:
        f.close()
