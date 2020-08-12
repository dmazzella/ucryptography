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
    print('{:6.3f}'.format(delta_t/1000))
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))


def derive(curve, private_value):
    t = utime.ticks_us()
    pr_k = crypto_ec.derive_private_key(private_value, curve)
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))


def generate(curve):
    t = utime.ticks_us()
    pr_k = crypto_ec.generate_private_key(curve)
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value",
          hex(pr_k.private_numbers().private_value))
    pu_k = pr_k.public_key()
    print("public_key.public_bytes()", pu_k.public_bytes())
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)

    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b'\x25' * 100)
    msg_hash = digest.finalize()

    t = utime.ticks_us()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    t = utime.ticks_us()
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(
        crypto_utils.Prehashed(chosen_hash)))
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))


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
