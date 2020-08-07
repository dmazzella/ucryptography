# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec, utils as crypto_utils

import time


def main():
    t = time.time()
    private_value = 30140591704819636439763775594845282823510480635318954373469177244302428654865
    pr_k = crypto_ec.derive_private_key(private_value, crypto_ec.SECP256R1(), default_backend())
    pu_k = pr_k.public_key()
    print(pu_k.public_numbers().x, pu_k.public_numbers().y)
    digest = crypto_hashes.Hash(crypto_hashes.SHA256(), default_backend())
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))
    print(signature)
    pu_k.verify(signature, msg_hash, crypto_ec.ECDSA(crypto_utils.Prehashed(crypto_hashes.SHA256())))
    pr_k1 = crypto_ec.generate_private_key(crypto_ec.SECP256R1(), default_backend())
    delta_t = time.time() - t
    print('{:6.3f}'.format(delta_t/1000))
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)


if __name__ == "__main__":
    main()
