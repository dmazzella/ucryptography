# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import ec, rsa, serialization, hashes, utils

try:
    from util import loads_sequence
except ImportError:
    try:
        from ucryptography.util import loads_sequence
    except ImportError:
        from ubinascii import a2b_base64
        from uio import BytesIO

        def loadf_sequence(f):
            f.seek(f.read().index(b"-----BEGIN") or 0)
            l = f.readline()
            if not l.startswith(b"-----BEGIN"):
                # not a pem
                f.seek(0)
                data = f.read()
                if data.startswith(b"\x30"):
                    return data
                return a2b_base64(data)

            # pem
            lines = []
            while 1:
                l = f.readline()
                if l == b"" or l.startswith(b"-----END"):
                    break
                lines.append(l)
            return a2b_base64(b"".join(lines).replace(b"\n", b""))

        def load_sequence(filename):
            f = open(filename, "rb")
            try:
                return loadf_sequence(f)
            finally:
                f.close()

        def loads_sequence(s):
            f = BytesIO(bytes(s, "utf-8"))
            try:
                return loadf_sequence(f)
            finally:
                f.close()


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
        private_key = serialization.load_der_private_key(EC_PRIVATE_KEY_DER, None)
        print("curve", private_key.curve.name)
        print("key_size", private_key.key_size)

        print("private_bytes", private_key.private_bytes())
        print(
            "private_bytes DER", private_key.private_bytes(serialization.Encoding.DER)
        )
        print(
            "private_bytes PEM",
            private_key.private_bytes(serialization.Encoding.PEM).decode(),
        )

        private_numbers = private_key.private_numbers()
        print("private_numbers.private_value: ", private_numbers.private_value)

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        print("public_key.curve", public_key.curve.name)
        public_bytes = public_key.public_bytes()
        print("public_key.public_bytes", public_bytes)
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
        public_bytes1 = public_key1.public_bytes()
        print("public_key.public_bytes", public_bytes1)
        print("public_key.public_numbers.x", public_numbers1.x)
        print("public_key.public_numbers.y", public_numbers1.y)
        public_key1.verify(signature, msg_hash, ec.ECDSA(utils.Prehashed(chosen_hash)))

    def rsa_serialization():
        private_key = serialization.load_der_private_key(RSA_PRIVATE_KEY_DER, None)
        public_numbers = private_key.public_key().public_numbers()
        print("n", public_numbers.n)
        print("e", public_numbers.e)

        print("key_size", public_numbers.public_key().key_size)
        print("private_bytes", private_key.private_bytes())
        print(
            "private_bytes DER", private_key.private_bytes(serialization.Encoding.DER)
        )
        print(
            "private_bytes PEM",
            private_key.private_bytes(serialization.Encoding.PEM).decode(),
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
            rsa.rsa_recover_prime_factors(
                public_numbers.n, public_numbers.e, private_numbers.d
            ),
        )

        public_key1 = serialization.load_der_public_key(RSA_PUBLIC_KEY_DER)
        public_numbers1 = public_key1.public_numbers()
        public_bytes1 = public_key1.public_bytes(serialization.Encoding.DER)
        print("public_key.public_bytes", public_bytes1)

    ec_serialization()
    rsa_serialization()


if __name__ == "__main__":
    main()
