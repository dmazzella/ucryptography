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
    public_bytes = pu_k.public_bytes()
    print("public_key.public_bytes()", public_bytes)
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
    public_bytes = pu_k.public_bytes()
    print("public_key.public_bytes()", public_bytes)
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
    public_bytes = pu_k.public_bytes()
    print("public_key.public_bytes()", public_bytes)
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


def main():
    curve = crypto_ec.SECP521R1()

    Qx = 0x1b62db4029cbfa12a1629775657a246f3b7df62c1fffb4d62c1133b3fd1df5102530655c258fe82a8e21ee55d8e6517bf99228e194cc79482a42e6abce61e83b81c
    Qy = 0x1b313a0fca150d1149c8a639e36187f6300e46644c2c4caff515bc024479fe91f8fca192b5abc5ab1fc2a5dbd1497d3447b825bc9ee480b2721f4c8136599a81453
    d = 0x1cc99dd29f51887222c526c4401b5fd5b8b7137a49ede9777ba1befaedaf0f3a2039fdc2afa91b155b8b874c33c5e10212307d78bb29299bfc53007b43bb0b6b7ed

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
