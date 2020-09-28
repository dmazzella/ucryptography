# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import ec, serialization, hashes, utils

try:
    from util import loads_sequence
except ImportError:
    try:
        from ucryptography.util import loads_sequence
    except ImportError:
        from ubinascii import a2b_base64
        from uio import BytesIO

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


PRIVATE_KEY_DER = loads_sequence(
    """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEKi+GleZpNE2E+oHgtnSkvTfAQ8zGhM+OHjqo74DM0RoAoGCCqGSM49
AwEHoUQDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuOORNL6DeWlqbnKMK1l7xf3wNe
1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END EC PRIVATE KEY-----"""
)


PUBLIC_KEY_DER = loads_sequence(
    """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuO
ORNL6DeWlqbnKMK1l7xf3wNe1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END PUBLIC KEY-----"""
)


def main():
    private_key = serialization.load_der_private_key(PRIVATE_KEY_DER, None)
    print("curve", private_key.curve.name)
    print("key_size", private_key.key_size)

    print("private_bytes", private_key.private_bytes())
    print("private_bytes DER", private_key.private_bytes(serialization.Encoding.DER))
    print("private_bytes PEM", private_key.private_bytes(serialization.Encoding.PEM))

    private_numbers = private_key.private_numbers()
    print("private_numbers.private_value: ", private_numbers.private_value)

    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    print("public_key.curve", public_key.curve.name)
    public_bytes = public_key.public_bytes()
    print("public_key.public_bytes", public_bytes)
    print("public_key.public_numbers.x", public_numbers.x)
    print("public_key.public_numbers.y", public_numbers.y)

    chosen_hash = hashes.SHA256()
    digest = hashes.Hash(chosen_hash)
    digest.update(b"cacca")
    digest.update(b"cacca")
    digest.update(b"cacca")
    digest.update(b"cacca")
    digest.update(b"cacca")
    msg_hash = digest.finalize()

    signature = private_key.sign(msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)
    public_key.verify(signature, msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))

    public_key1 = serialization.load_der_public_key(PUBLIC_KEY_DER)
    public_numbers1 = public_key1.public_numbers()
    print("public_key.curve", public_key1.curve.name)
    public_bytes1 = public_key1.public_bytes()
    print("public_key.public_bytes", public_bytes1)
    print("public_key.public_numbers.x", public_numbers1.x)
    print("public_key.public_numbers.y", public_numbers1.y)
    public_key1.verify(signature, msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))


if __name__ == "__main__":
    main()
