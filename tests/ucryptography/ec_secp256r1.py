# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable
import utime
from cryptography import ec as crypto_ec
from cryptography import hashes as crypto_hashes
from cryptography import utils as crypto_utils


def numbers(curve, x, y, private_value):
    t = utime.ticks_us()
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key()
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(
            crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))

    message = b"A message I want to sign"
    print("message", message, len(message))

    t = utime.ticks_us()
    signature = pr_k.sign(message, crypto_ec.ECDSA(None))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))

    print("signature", signature, len(signature))

    t = utime.ticks_us()
    pu_k.verify(signature, message, crypto_ec.ECDSA(None))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))


def derive(curve, private_value):
    t = utime.ticks_us()
    pr_k = crypto_ec.derive_private_key(private_value, curve)
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(
            crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))


def generate(curve):
    t = utime.ticks_us()
    pr_k = crypto_ec.generate_private_key(curve)
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(
        msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(
        signature, msg_hash, crypto_ec.ECDSA(
            crypto_utils.Prehashed(chosen_hash))
    )
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print("{:6.3f}".format(delta_t / 1000))


def main():
    curve = crypto_ec.SECP256R1()

    Qx = 0xC150D3429B39371D85E9046DF28EBE68B40EF530D3F3D58E6208F0E38C6762BA
    Qy = 0xD619E7ECD3728BFE7AC0DEE9B915B80B8006CA4308E91B3F58C2ACC39D53D974
    d = 0x76B81AB1AFE277BA098688808F4BAC472FF36D3094332AE62344C060F7B0055E

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
