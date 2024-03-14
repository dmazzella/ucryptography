# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable
try:
    from cryptography import ed25519, serialization
except ImportError:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519


def main():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("private_bytes", private_bytes)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("public_bytes", public_bytes)

    signature = private_key.sign(b"my authenticated message")
    print("signature", signature)
    public_key.verify(signature, b"my authenticated message")

    private_bytes = b"\x91\xc4\x1b{\x12>\xa1\x92'\x96\xc1\xf8\x8c\x1d\xf0\x16,\xdc\xb3M*C-\x02Q\xf5\xfflD\x8dA>"
    public_bytes = b"_#%t\xdf\xd3\x03\xe0\xe1\xc2\x9b\xd6\x174\x94R\xf9\x10\xe6\x9aK<\xb52\x0b(\xfad\xd2\xb9\xcc\x0b"
    signature = b'\xd7\'\xdb\xc3\x01}(w\x11\xb3\xd7\x05\xb3?-@Y\x82q3\x11\xbfF"\xbb\x14E\xee\xdfA\x02\xf7\xae\x02\x83\xd8\xb4\x84\x05=\xe8n9\xbb\xbfM\x7f\x9d"\x19@\xc4.\xd8O\xb5\xbd\xc0\xe3\x97a;s\x05'

    loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    loaded_signature = loaded_private_key.sign(b"my authenticated message")
    print("loaded_signature", loaded_signature)
    loaded_public_key.verify(loaded_signature, b"my authenticated message")

    print("signature", signature)
    loaded_public_key.verify(signature, b"my authenticated message")


if __name__ == "__main__":
    main()
