# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec as crypto_ec,
    utils as crypto_utils,
)
from cryptography.hazmat.backends.openssl.ec import _ecdsa_sig_sign, _ecdsa_sig_verify
from cryptography.hazmat.primitives import serialization


def numbers(curve, x, y, private_value):
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key(default_backend())
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    public_bytes = pu_k.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    print("public_key.public_bytes()", public_bytes)
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )

    message = b"A message I want to sign"
    signature = _ecdsa_sig_sign(default_backend(), pr_k, message)
    print("message", message, len(message))
    print("signature", signature, len(signature))
    _ecdsa_sig_verify(default_backend(), pu_k, signature, message)


def derive(curve, private_value):
    pr_k = crypto_ec.derive_private_key(private_value, curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    public_bytes = pu_k.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    print("public_key.public_bytes()", public_bytes)
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )


def generate(curve):
    pr_k = crypto_ec.generate_private_key(curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    public_bytes = pu_k.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    print("public_key.public_bytes()", public_bytes)
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )


def main():
    curve = crypto_ec.SECP521R1()

    Qx = 0x1B62DB4029CBFA12A1629775657A246F3B7DF62C1FFFB4D62C1133B3FD1DF5102530655C258FE82A8E21EE55D8E6517BF99228E194CC79482A42E6ABCE61E83B81C
    Qy = 0x1B313A0FCA150D1149C8A639E36187F6300E46644C2C4CAFF515BC024479FE91F8FCA192B5ABC5AB1FC2A5DBD1497D3447B825BC9EE480B2721F4C8136599A81453
    d = 0x1CC99DD29F51887222C526C4401B5FD5B8B7137A49EDE9777BA1BEFAEDAF0F3A2039FDC2AFA91B155B8B874C33C5E10212307D78BB29299BFC53007B43BB0B6B7ED

    try:
        print("@" * 20, "NUMBERS", "@" * 20)
        numbers(curve, Qx, Qy, d)
    except Exception as ex:
        print(type(ex), ex)

    try:
        print("@" * 20, "DERIVE", "@" * 20)
        derive(curve, d)
    except Exception as ex:
        print(type(ex), ex)

    try:
        print("@" * 20, "GENERATE", "@" * 20)
        generate(curve)
    except Exception as ex:
        print(type(ex), ex)


if __name__ == "__main__":
    main()
