# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import ec, hashes


def main():

    x = 29583689448130623549461599781746453699482826879078938126643502770938790226114
    y = 82136719613346909890578322550509883175409280878753479486152615526666878310478
    ecpubn = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())

    private_value = 30140591704819636439763775594845282823510480635318954373469177244302428654865
    ecprivn = ec.EllipticCurvePrivateNumbers(private_value, ecpubn)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    digest.update(b'cacca')
    msg_hash = digest.finalize()
    signature = ecprivn.private_key().sign(msg_hash)
    print("len", len(signature), "signature", signature, "msg_hash", msg_hash)
    ecpubn.public_key().verify(signature, msg_hash)


if __name__ == "__main__":
    main()
