# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable
try:
    from cryptography import ec as crypto_ec
    from cryptography import hashes as crypto_hashes
    from cryptography import utils as crypto_utils
    from cryptography import serialization as crypto_serialization
except ImportError:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
    from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils


def numbers(curve, x, y, private_value):
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key()
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    print(
        "private_bytes DER",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ),
    )
    print(
        "private_bytes PEM",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ).decode(),
    )
    pu_k = pr_k.public_key()
    print(
        "public_key.public_bytes X962",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.X962,
            format=crypto_serialization.PublicFormat.UncompressedPoint,
        ),
    )
    print(
        "public_key DER",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    print(
        "public_key PEM",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)
    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))
    message = b"A message I want to sign"
    print("message", message, len(message))
    signature = pr_k.sign(message, crypto_ec.ECDSA(None))
    print("signature", signature, len(signature))
    pu_k.verify(signature, message, crypto_ec.ECDSA(None))


def derive(curve, private_value):
    pr_k = crypto_ec.derive_private_key(private_value, curve)
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    print(
        "private_bytes DER",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ),
    )
    print(
        "private_bytes PEM",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ).decode(),
    )
    pu_k = pr_k.public_key()
    print(
        "public_key.public_bytes X962",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.X962,
            format=crypto_serialization.PublicFormat.UncompressedPoint,
        ),
    )
    print(
        "public_key DER",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    print(
        "public_key PEM",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)
    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))


def generate(curve):
    pr_k = crypto_ec.generate_private_key(curve)
    print("private_key.curve", pr_k.curve)
    print(
        "private_key.private_numbers().private_value",
        hex(pr_k.private_numbers().private_value),
    )
    print(
        "private_bytes DER",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ),
    )
    print(
        "private_bytes PEM",
        pr_k.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ).decode(),
    )
    pu_k = pr_k.public_key()
    print(
        "public_key.public_bytes X962",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.X962,
            format=crypto_serialization.PublicFormat.UncompressedPoint,
        ),
    )
    print(
        "public_key DER",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    print(
        "public_key PEM",
        pu_k.public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )
    print("public_key.public_numbers().x", hex(pu_k.public_numbers().x))
    print("public_key.public_numbers().y", hex(pu_k.public_numbers().y))
    print("public_key.curve", pu_k.curve)
    chosen_hash = crypto_hashes.SHA256()
    digest = crypto_hashes.Hash(chosen_hash)
    digest.update(b"\x25" * 100)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))
    print("msg_hash", msg_hash, len(msg_hash))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(chosen_hash)))


def main():
    curve = crypto_ec.SECP384R1()

    Qx = 0xBE840AAB595C86298B60C7AB9EBCB198CE3E9F884C5FF403A3EB67ABABDC2312FEBEFB16A0913BD1E66B07371ABAD8FC
    Qy = 0x6E218AB3DC163166FBE6F10824B0E1850A838E68DB798BF3EFF483841A16628C00458EA9D116AB53B0557514CE9BA5B7
    d = 0x94F45B7DE01D13CE1AE70219F011B6BB05C2B0B552C755CAE9D9714C072F55537EA94ED86511E8C7956B10A812125DFA

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
