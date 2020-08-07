# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec, utils


def main():
    curve = crypto_ec.SECP521R1()
    print(curve)
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

    private_value = 4148403465628481883223364328054647195765416478037794978681683443491707303680159450884004123963819481522884437450650150540572139671234348130584068389660889384
    pr_k = crypto_ec.derive_private_key(private_value, curve, default_backend())
    print("private_key.curve", pr_k.curve)
    print("private_key.private_numbers().private_value", pr_k.private_numbers().private_value)
    pu_k = pr_k.public_key()
    print("public_key.public_numbers().x", pu_k.public_numbers().x)
    print("public_key.public_numbers().y", pu_k.public_numbers().y)
    print("public_key.curve", pu_k.curve)


if __name__ == "__main__":
    main()
