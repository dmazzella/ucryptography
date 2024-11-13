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

RSA_ENCRYPTED_PRIVATE_KEY_DER = loads_sequence(
    """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6jAcBgoqhkiG9w0BDAEDMA4ECGkBlv9nOvrlAgIIAASCBMhT9pWzij8iyruh
rV1CBfDaz8gQpOCvAB8e8SY2W6Btzd3VX290VmXWKC0Y/018bdVRFXch5AZiJJwC
J4+b7RloH1fATkqoesBVPEAy7GIPOpzSRF+0qXsqp5pPpVDGv77kEYc8tkC0l9E0
bmJ27YGVoVjmsmKoLcrP3PvykR1S8AQgVnav8+km2b0J0mkCOTCXWEGvMuGHhZXJ
oSFoCBHgCfgTLoL8tx/lt/pOWFHYe3oeTSEOJqMFu7Q4LVtRlXOHv0rH9z7Xb7PF
36PsBcaoOH0bsylRFQGBtR+RIpe00jR8W+BfQavtUo+fpiE97OJR3uFYZOM3tTBs
d8XDa5VwBxqld3hpmrHa/svWxARvE9z0OgdFu/5UEUA87Bjc1y+CoVXcUmfBYbRV
gEYfClNoYmZpu1XxGV6sDtpOsKTPytai5iKYrtJ3UFT6OOrgXzLP8a3ZCm1Talec
bhVnx4ZEb8SKNlu5Bhc4PmGYooYi1bJyveFlWWBLlHfo+sF3sNYcufpbtuZkn1Op
0R+Ag+P8Mh2cKKx/hIOliXnhkmntAajdP5fzhLpEP+POmAFnN8cA08nAYhOrDDBY
MDP1OxONoz6Rjtm9jPIGuNV76DE57oUZD884U8qthQRxb4XX+sTLrZOqQpmPN4Vw
i5O6nBwexfMibAhrChIwHXvPElmpUW0pHJc1YFE1yuZWS+y+G+yg9aCAVJVTdkfa
mJrPLtiU1WoDB7Wad9PFp5Pe6acOiPlAVWOLf85800oSKX19FA23rMnc8y/PTRuF
Br4fRKPHSAgkvx0O5AKhOgyk1QiDbAX3gYL3Vmmb6GGYu1X+EwUTq58TEREICgvK
4SDwjc3p+svesvNPt1WjCPbDgxOCdEBx8V+NrbfO1o8xHTVkoDj0beWWgH4p39n5
uNLvkxh0Oj8BlTipDp93EX8gdc3VGR8KvCHnzFNgxhaA7My3UjUH0V+9yg0+zTpG
AlO0X9FJqwCK54+cEseusl65606hmZsjMRLltGcmZn74UCJ8bHiVzzuVPovK5GkT
pfwkh0bw6TyqUrLuxVNFu9rw2HvPTjv3GycmaMv4Dd5BWbhkwk3MOUsGPHTNNHYR
XlcWlv9ul3fJDevQu2tBmfJhrlvuldvHxtuJlieS968AYQjL0zN4R5vwCYKIdde+
K9xpWIpqI1dqh5XvR6aCDuMn6f7r403XwNqQK3szhqTW0ZcYlTxc+EAIWnpGpFlC
5X708LnDDMofbYn6zW+U53rcUmBeQAdlUFG3a4Qp/oM2WmX2U3U1cxeIa5Hets90
8lzr+jllKuZveCyCB6PJBUohqb4ezbnQmkqfCw4PdgPY0rUsB71ursZDa18Acjah
Ugya2tPwts84s54gDZg3o8rL9jqkK/dbLO+a0zCzWFvXZCChh+Q+CjMUBdtNOfdQ
b5uneZqn7HyPn/3N4a8b5viteO9YUmHSDHFhU6Jm5jL5bXwTB4Jwp76a3KZ9NCd3
pvU1SpL9d0iXPXB/LRB+vKBkgRHoaPCmB8FTv+WNOFCCq5HS/zMoQIZDGkWQIQ/q
r7ZvofgSjtCPSWaC1jsxObGU6ogF69/+BMvTzkyPqSfsmpDrewiaRPTfib1Uc8gK
NvOosXfO9XHxf/uLMN0=
-----END ENCRYPTED PRIVATE KEY-----"""
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

    def rsa_e_serialization():
        # openssl genrsa -out key.pem 2048
        # openssl pkcs8 -in key.pem -outform PEM -out pkcs8.key -v1 PBE-SHA1-3DES -topk8
        private_key = serialization.load_der_private_key(RSA_ENCRYPTED_PRIVATE_KEY_DER, b'password')
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
    rsa_e_serialization()


if __name__ == "__main__":
    main()
