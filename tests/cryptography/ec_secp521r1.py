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
