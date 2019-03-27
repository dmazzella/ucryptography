# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def main():
    x = 29583689448130623549461599781746453699482826879078938126643502770938790226114
    y = 82136719613346909890578322550509883175409280878753479486152615526666878310478
    ecpubn = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())

    private_value = 30140591704819636439763775594845282823510480635318954373469177244302428654865
    ecprivn = ec.EllipticCurvePrivateNumbers(private_value, ecpubn)

    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    msg_hash = digest.finalize()
    signature = ecprivn.private_key(default_backend()).sign(
        msg_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)
    ecpubn.public_key(default_backend()).verify(
        signature, msg_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


if __name__ == "__main__":
    main()
