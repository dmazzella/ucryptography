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

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))


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

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))


def generate(curve):
    pr_k = crypto_ec.generate_private_key(curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash, default_backend())
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))


def main():
    curve = crypto_ec.SECP384R1()

    Qx = 0xbe840aab595c86298b60c7ab9ebcb198ce3e9f884c5ff403a3eb67ababdc2312febefb16a0913bd1e66b07371abad8fc
    Qy = 0x6e218ab3dc163166fbe6f10824b0e1850a838e68db798bf3eff483841a16628c00458ea9d116ab53b0557514ce9ba5b7
    d = 0x94f45b7de01d13ce1ae70219f011b6bb05c2b0b552c755cae9d9714c072f55537ea94ed86511e8c7956b10a812125dfa

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