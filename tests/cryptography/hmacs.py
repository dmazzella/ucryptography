# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
try:
    from cryptography import hashes, hmac
except ImportError:
    from cryptography.hazmat.primitives import hashes, hmac


def _flip_last(b):
    a = bytearray(b)
    a[-1] ^= 0x01
    return bytes(a)


def _assert_rejected(label, fn):
    try:
        fn()
    except Exception as ex:
        print("  reject OK:", label, "->", type(ex).__name__)
        return
    raise AssertionError("SECURITY: tampered input accepted -> " + label)


def _verify(ctx, data, signature):
    ctx.update(data)
    ctx.verify(signature)


def main():
    expected_sha1 = b"U#\x8d\xfb\x08\x96'a&B\xa5=\xf7\xed\xc2{\x83\xb9\xd0\xab"
    expected_sha256 = b"\x80\x1c\x18\n\xc0\xc9W=p\xcan\x1a\x0f\xb6\n\x0b\xe9\x8d\xdf\xb3\xc3\xe6\xea+\x8b\xa9:Na4\xd8\x9c"
    expected_sha384 = b"\xc3\x01O;\xc7a\x86\xbc\xa8v\x05Vt\x95\x83W\xaa\x16\xfc\xc9\xf7\xa6~S\x85\xed\xb4-\xc6t\xb2.\xdf^\xdee\x17\xda\x1a\xed\x168\xa7:SD\xf1'"
    expected_sha512 = b"\xdf\xe9\x07\xe6\xf5\x10r\xcf\x9bM*J\xf8\xe3\xf7\xa4\xd3O6z\x1d\x03\xa6\xce\xbd\xe1\x0f\x8b\xb1/O\xdb\xdd-M\xe0b\xaar\x87\xc4\xeaW\x91\x8e\x8b\xd5\x8c\x8e\xe5\xd86\xb0\x81;\xe1RaL\xdd\xbf)\x12D"
    expected_blake2s = b"\xd0 \xa8\xcdK2\xdf\x850sBXt\x9c\xcf7\xaa\x98\xc7v\xb0x\x90u\xd3s\xa0/=\xbf\xb7\xad"

    key = (
        b"\x93\x8dYL%\xd7;dV\x94D+$\x86\x12gD\xe6\x99x\xdf2\x82\x08Y\x05\xb5m\x8d}\x15}"
    )

    hmac_context = hmac.HMAC(key, hashes.SHA1())
    hmac_context.update(b"caccone" * 1000)
    print(expected_sha1 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.SHA256())
    hmac_context.update(b"caccone" * 1000)
    print(expected_sha256 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.SHA384())
    hmac_context.update(b"caccone" * 1000)
    print(expected_sha384 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.SHA512())
    hmac_context.update(b"caccone" * 1000)
    print(expected_sha512 == hmac_context.finalize())

    hmac_context = hmac.HMAC(key, hashes.BLAKE2s(32))
    hmac_context.update(b"caccone" * 1000)
    print(expected_blake2s == hmac_context.finalize())

    # --- HMAC.verify() tamper guards ---------------------------------------
    # verify() must recompute the MAC and reject a wrong/forged/truncated tag
    # instead of silently accepting it (fail-open).
    hmac_context = hmac.HMAC(key, hashes.SHA256())
    hmac_context.update(b"caccone" * 1000)
    hmac_context.verify(expected_sha256)  # correct tag: must NOT raise
    print("HMAC verify (valid) OK")

    _assert_rejected(
        "HMAC wrong signature",
        lambda: _verify(
            hmac.HMAC(key, hashes.SHA256()),
            b"caccone" * 1000,
            _flip_last(expected_sha256),
        ),
    )
    _assert_rejected(
        "HMAC tampered data",
        lambda: _verify(
            hmac.HMAC(key, hashes.SHA256()), b"tampered data", expected_sha256
        ),
    )
    _assert_rejected(
        "HMAC truncated signature",
        lambda: _verify(
            hmac.HMAC(key, hashes.SHA256()), b"caccone" * 1000, expected_sha256[:16]
        ),
    )
    print("HMAC verify tamper tests passed")

    # --- HMAC.copy() must duplicate key + buffered data + hash algorithm ----
    # A broken copy (missing key/hash_context) would crash or mis-verify here.
    base = hmac.HMAC(key, hashes.SHA256())
    base.update(b"caccone" * 1000)
    clone = base.copy()
    print("HMAC copy finalize matches:", clone.finalize() == expected_sha256)
    fork = hmac.HMAC(key, hashes.SHA256())
    fork.update(b"caccone" * 1000)
    fork.copy().verify(expected_sha256)
    print("HMAC copy verify OK")


if __name__ == "__main__":
    main()
