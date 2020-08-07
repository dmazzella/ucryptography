# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec, utils as crypto_utils


def main():
    curve = crypto_ec.SECP521R1()
    print(curve)

    private_value = 4148403465628481883223364328054647195765416478037794978681683443491707303680159450884004123963819481522884437450650150540572139671234348130584068389660889384
    pr_k = crypto_ec.derive_private_key(private_value, curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("signature", signature, len(signature))
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))

    x = 4581532043671755688726325986504888924201577996143378104945916052211204722889886305856867530652495019769916389469936565534571514535030765774930443829353543043
    y = 2940306895387008863308602118054866324635506181433035815073542849436352773523096012327187317795056752386332057481300507565435285875573493738286918043552245537
    ecpubn = crypto_ec.EllipticCurvePublicNumbers(x, y, curve)
    private_value = 4148403465628481883223364328054647195765416478037794978681683443491707303680159450884004123963819481522884437450650150540572139671234348130584068389660889384
    ecprivn = crypto_ec.EllipticCurvePrivateNumbers(private_value, ecpubn)
    pr_k = ecprivn.private_key(default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))

    t = time.time()
    pr_k = crypto_ec.generate_private_key(curve, default_backend())
    delta_t = time.time() - t
    print('{:6.3f}'.format(delta_t/1000))
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)

    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'\xff' * 64)
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print("signature", signature)
    print("decode_dss_signature", crypto_utils.decode_dss_signature(signature))
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))

if __name__ == "__main__":
    main()
