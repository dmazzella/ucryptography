# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=unused-variable
from cryptography import ec as crypto_ec
from cryptography import hashes as crypto_hashes

import utime


def main():
    t = utime.ticks_us()
    private_value = 30140591704819636439763775594845282823510480635318954373469177244302428654865
    pr_k = crypto_ec.derive_private_key(private_value, crypto_ec.SECP256R1())
    pu_k = pr_k.public_key()
    print(pu_k.public_numbers().x, pu_k.public_numbers().y)
    digest = crypto_hashes.Hash(crypto_hashes.SHA256())
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    msg_hash = digest.finalize()
    signature = pr_k.sign(msg_hash)
    pu_k.verify(signature, msg_hash)
    pr_k1 = crypto_ec.generate_private_key(crypto_ec.SECP256R1())
    delta_t = utime.ticks_diff(utime.ticks_us(), t)
    print('{:6.3f}'.format(delta_t/1000))
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)


if __name__ == "__main__":
    main()
