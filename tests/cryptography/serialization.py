# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import binascii

try:
    from cryptography import ec, rsa, serialization, hashes, utils
except ImportError:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import utils
try:
    from util import loads_sequence
except ImportError:
    raise


EC_PRIVATE_KEY_DER = loads_sequence(
    """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEKi+GleZpNE2E+oHgtnSkvTfAQ8zGhM+OHjqo74DM0RoAoGCCqGSM49
AwEHoUQDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuOORNL6DeWlqbnKMK1l7xf3wNe
1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END EC PRIVATE KEY-----"""
)

EC_PUBLIC_KEY_DER = loads_sequence(
    """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQWfGXJw+X9PV2czte6S4pXBM4QuO
ORNL6DeWlqbnKMK1l7xf3wNe1GZQ5vs4617zr3nCVjPhbs1qCCi8Ny/YTg==
-----END PUBLIC KEY-----"""
)

EC_PUBLIC_KEY_UNCOMPRESSED = binascii.unhexlify(
    b"046fb0b63f7844c499106838d1fb14980ba52587a418dfeee55ffff93e0a208b3336dc00499ee94c54276d38c9769b746ae54dff5d6b6eacb590b56417dd2422c1"
)

RSA_PRIVATE_KEY_DER = loads_sequence(
    """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1wJT+JTwNGPPb2SydhwhF+tU/wx8JeZkr1Pe9TNkzLMznBE3
pIWA9MOapVTicaxezyWnd1NTnc+aeLvvtLfZ7qII4emaE04lNUl+a7hHGhZ4iyn5
PgJlOgwXhqrAr27v2XlyZWHajJ/EU9Q2AE5p3eUB1I5cm53thPObt102kZ5LXuDt
huUPrKMm5cqFyQg4CqUEXZWai+gBCQWdhnUlQnPoepGUdIvDjgbNl37LKXNllPrF
Ch0tlSRC4K5lItHN4KJ602r3lE4WK2HCpvN6nNFU1w65WMs3zAjxfWgp+K4NBGTl
B5kPYqS3fzaSw8TrmC48lazpVhpyu4cQhwvEMwIDAQABAoIBAGY3uB4lCLGPhg3K
TMG0C9OoUOdUUy1dhB6KfCQMg+6Bf5bB5Lc1tSIoYDwbx/AM56IJn70uA0GychjW
GFbNVTGLHTfx7AsjirLztsOVf1AawMJAeTsOvntDRmgCg8qjrimxAD7Mr69NQXQt
HmM05EXW2vDnoYVmJoafnjclfIzrWgL3HQ9zLQrLCx7S1E8P6OqeholBO1f/QK5i
vWVkWMNYCucXjTaVjoOADCQvnvWQ+Qtrutgw7H/Pat9AHEMmLuptb+0CcGqlbDOT
5IP0qDFs0x9FzuMTjzHaFTy0XLYdnYA9bVoz1VNRpjUfa6GeK8USaSMcj8frUMmP
PceMNHECgYEA+3Jt7SpLY8odr3LMXplyhfG6QaUOy5gRI0Sbp4v9XLnAJ/SmH9re
O3FEg0FFGXx9oZIRI7H4+z1kBjxtuH8NXy9n90QFOusHDMkaYa14gGj1YdnyniFu
SbupI6rCVEfDAn6qazzoY4S29/SEmamM00GT7HJAh0frvUupg/9fbQsCgYEA2ub+
Eqe2kIyJFSHY9t2mA4SdWibeA05MLNqDQL0iWwkvNd6QNZIe4Hi6s4nRhDZjktMP
1aageRjJ97/X98kGd60TjHA+73RjtpyCD1hnVKHWFABp0w1XJLEYDqTo/AAfPk27
4Dq0F+EPM4bvZJ9igVWXNrZebrA345Cug+NT7nkCgYEA1YlQIWERtSUoIJ91P8FA
qM+oRadO8UerBjB1n8wa1mxI66WwjszofcKrVGxRqls2tce+FnpF39c64rDe3RfI
21T/DdYOOwLtccY3SUxwUVzRRtA4YmIxrxxXf5q8faaTzcKUJ44KLLnASMK2+Wgr
2ByQ6vP8KObDJHbk9twgxhECgYEArXP/uxR9ywgwzzfkzahQFdWNQZQus3vlTF1R
R4kWogAjEpJqvqgsIz5G4mDATf0y5XKsx2SjH5GO5+tx2/vETiwso0mF9QPKxzY4
sKQiLKOYGH1DXWLivEY/g8sUeio2l43M4x5g+dLx0qiHJLpOuaDykv3q0dZ8Uqug
PQ1ywjECgYAE/WV2tSRmqj2JxRxc5/nULvIbFcdecx3Nf6AxRclRLV8LzrNGJckT
/GIiQqUxQJxFmSjvyCuPnycweqXRAufQ/aAUTPu6NSGD9nm+pOEtg6hQt/d6v4W+
Q3TO9t6xTr49ZE20GLkFWUWV8+qLeZLbhntR6gDZ16ElKHAL4v9z3g==
-----END RSA PRIVATE KEY-----"""
)

RSA_PUBLIC_KEY_DER = loads_sequence(
    """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1wJT+JTwNGPPb2Sydhwh
F+tU/wx8JeZkr1Pe9TNkzLMznBE3pIWA9MOapVTicaxezyWnd1NTnc+aeLvvtLfZ
7qII4emaE04lNUl+a7hHGhZ4iyn5PgJlOgwXhqrAr27v2XlyZWHajJ/EU9Q2AE5p
3eUB1I5cm53thPObt102kZ5LXuDthuUPrKMm5cqFyQg4CqUEXZWai+gBCQWdhnUl
QnPoepGUdIvDjgbNl37LKXNllPrFCh0tlSRC4K5lItHN4KJ602r3lE4WK2HCpvN6
nNFU1w65WMs3zAjxfWgp+K4NBGTlB5kPYqS3fzaSw8TrmC48lazpVhpyu4cQhwvE
MwIDAQAB
-----END PUBLIC KEY-----"""
)


def main():
    def ec_serialization():
        public_key_u = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), EC_PUBLIC_KEY_UNCOMPRESSED
        )
        print("public_key.curve", public_key_u.curve.name)
        public_numbersu = public_key_u.public_numbers()
        print("public_key.public_numbers.x", public_numbersu.x)
        print("public_key.public_numbers.y", public_numbersu.y)
        print(
            "public_key.public_bytes X962",
            public_key_u.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ),
        )
        print(
            "public_key DER",
            public_key_u.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        print(
            "public_key PEM",
            public_key_u.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

        private_key = serialization.load_der_private_key(EC_PRIVATE_KEY_DER, None)
        print("curve", private_key.curve.name)
        print("key_size", private_key.key_size)

        print(
            "private_bytes DER",
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        print(
            "private_bytes PEM",
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
        )

        private_numbers = private_key.private_numbers()
        print("private_numbers.private_value: ", private_numbers.private_value)

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        print("public_key.curve", public_key.curve.name)
        print(
            "public_key.public_bytes X962",
            public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ),
        )
        print(
            "public_key DER",
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        print(
            "public_key PEM",
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )
        print("public_key.public_numbers.x", public_numbers.x)
        print("public_key.public_numbers.y", public_numbers.y)

        chosen_hash = hashes.SHA256()
        digest = hashes.Hash(chosen_hash)
        digest.update(b"cacca")
        digest.update(b"cacca")
        digest.update(b"cacca")
        digest.update(b"cacca")
        digest.update(b"cacca")
        msg_hash = digest.finalize()

        signature = private_key.sign(msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))
        print("len", len(signature), "signature", signature, "msg_hash", msg_hash)
        public_key.verify(signature, msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))

        public_key1 = serialization.load_der_public_key(EC_PUBLIC_KEY_DER)
        public_numbers1 = public_key1.public_numbers()
        print("public_key.curve", public_key1.curve.name)
        print(
            "public_key.public_bytes X962",
            public_key1.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ),
        )
        print(
            "public_key DER",
            public_key1.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        print(
            "public_key PEM",
            public_key1.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )
        print("public_key.public_numbers.x", public_numbers1.x)
        print("public_key.public_numbers.y", public_numbers1.y)
        public_key1.verify(signature, msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))

    def rsa_serialization():
        private_key = serialization.load_der_private_key(RSA_PRIVATE_KEY_DER, None)
        public_numbers = private_key.public_key().public_numbers()
        print("n", public_numbers.n)
        print("e", public_numbers.e)
        print("key_size", public_numbers.public_key().key_size)

        print(
            "private_bytes DER",
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        print(
            "private_bytes PEM",
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
        )

        private_numbers = private_key.private_numbers()

        print("d", private_numbers.d)
        print("p", private_numbers.p)
        print("q", private_numbers.q)
        print("iqmp", private_numbers.iqmp)
        print("dmp1", private_numbers.dmp1)
        print("dmq1", private_numbers.dmq1)
        print("IQMP", rsa.rsa_crt_iqmp(private_numbers.p, private_numbers.q))
        print("DMP1", rsa.rsa_crt_dmp1(private_numbers.d, private_numbers.p))
        print("DMQ1", rsa.rsa_crt_dmq1(private_numbers.d, private_numbers.q))
        print(
            "P, Q",
            rsa.rsa_recover_prime_factors(public_numbers.n, public_numbers.e, private_numbers.d),
        )

        public_key1 = serialization.load_der_public_key(RSA_PUBLIC_KEY_DER)

        print(
            "public_key.public_bytes DER",
            public_key1.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        print(
            "public_key.public_bytes PEM",
            public_key1.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

    ec_serialization()
    rsa_serialization()


if __name__ == "__main__":
    main()
