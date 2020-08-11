# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec, utils as crypto_utils
from cryptography.hazmat.primitives import serialization


def numbers(curve, x, y, private_value):
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key(default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    public_bytes = pu_k.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("public_key.public_bytes()", public_bytes)
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))


def derive(curve, private_value):
    pr_k = crypto_ec.derive_private_key(
        private_value, curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    public_bytes = pu_k.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("public_key.public_bytes()", public_bytes)
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))


def generate(curve):
    pr_k = crypto_ec.generate_private_key(curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(crypto_hashes.SHA256())))


def main():
    curve = crypto_ec.SECP256R1()

    Qx = 0xc150d3429b39371d85e9046df28ebe68b40ef530d3f3d58e6208f0e38c6762ba
    Qy = 0xd619e7ecd3728bfe7ac0dee9b915b80b8006ca4308e91b3f58c2acc39d53d974
    d = 0x76b81ab1afe277ba098688808f4bac472ff36d3094332ae62344c060f7b0055e

    try:
        print("@"*20, "NUMBERS", "@"*20)
        numbers(curve, Qx, Qy, d)
    except Exception as ex:
        print(type(ex), ex)

    try:
        print("@"*20, "DERIVE", "@"*20)
        derive(curve, d)
    except Exception as ex:
        print(type(ex), ex)

    try:
        print("@"*20, "GENERATE", "@"*20)
        generate(curve)
    except Exception as ex:
        print(type(ex), ex)


if __name__ == "__main__":
    main()
