# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable
import utime
from cryptography import ec as crypto_ec
from cryptography import hashes as crypto_hashes
from cryptography import util as crypto_utils


def main():
    curve = crypto_ec.SECP256R1()
    print(curve)

    private_value = 53698200228583047627905205097146419258086512490010281329028019702673987077470
    pr_k = crypto_ec.derive_private_key(private_value, curve)
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash)
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash)

    x = 87439185605935278758799646727774972420229950662880336291586265063992599208634
    y = 96840721461660004171647959885473889920095908942704749023403573529516807805300
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    private_value = 53698200228583047627905205097146419258086512490010281329028019702673987077470
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key()
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash)
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash)

    t = utime.ticks_us()
    pr_k = crypto_ec.generate_private_key(curve)
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash)
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash)


if __name__ == "__main__":
    main()
