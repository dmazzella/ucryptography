# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def main():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("private_bytes", private_bytes)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print("public_bytes", public_bytes)

    signature = private_key.sign(b"my authenticated message")
    print("signature", signature)
    public_key.verify(signature, b"my authenticated message")

    loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    loaded_signature = loaded_private_key.sign(b"my authenticated message")
    print("loaded_signature", loaded_signature)
    loaded_public_key.verify(loaded_signature, b"my authenticated message")


if __name__ == "__main__":
    main()
