# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
from cryptography import x509, hashes, serialization, utils, ec, rsa, padding

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


EC_CERT_DER = loads_sequence(
    """-----BEGIN CERTIFICATE-----
MIICiDCCAi+gAwIBAgIUEkh9KHsIlsR5m73KoHd9dnoaE+EwCgYIKoZIzj0EAwIw
gZkxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEPMA0GA1UEBwwGTmFwb2xp
MRYwFAYDVQQKDA1CaXQ0aWQgcy5yLmwuMQwwCgYDVQQLDANSJkQxGTAXBgNVBAMM
EERhbWlhbm8gTWF6emVsbGExKDAmBgkqhkiG9w0BCQEWGWRhbWlhbm9tYXp6ZWxs
YUBnbWFpbC5jb20wHhcNMTkwMzE5MTMzNTU4WhcNMjAwMzE4MTMzNTU4WjCBmTEL
MAkGA1UEBhMCSVQxDjAMBgNVBAgMBUl0YWx5MQ8wDQYDVQQHDAZOYXBvbGkxFjAU
BgNVBAoMDUJpdDRpZCBzLnIubC4xDDAKBgNVBAsMA1ImRDEZMBcGA1UEAwwQRGFt
aWFubyBNYXp6ZWxsYTEoMCYGCSqGSIb3DQEJARYZZGFtaWFub21henplbGxhQGdt
YWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEFnxlycPl/T1dnM7Xuk
uKVwTOELjjkTS+g3lpam5yjCtZe8X98DXtRmUOb7OOte8695wlYz4W7NaggovDcv
2E6jUzBRMB0GA1UdDgQWBBR1cuI1e0csCOy/aY7P5zOeyPLShjAfBgNVHSMEGDAW
gBR1cuI1e0csCOy/aY7P5zOeyPLShjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0cAMEQCIGYm2Orv975+0CZZsKy7nYf4c5J+yTEKk329wk85CQ71AiBXXS5K
s+LnrOm0QFpFTo1ZoMRiLiDVvqR/exKUFMF6OA==
-----END CERTIFICATE-----"""
)

RSA_CERT_DER = loads_sequence(
    """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUCM7C8C0unyLHhGeSV9wFdNAqBvYwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdGVzdC5jb20wHhcNMjAxMDA1MDg0ODI3WhcNMjIwNTI4
MDg0ODI3WjATMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKs2GZ+MkmX4l77vX0TrsKKdiVhKl45nwc6iSM/rWJ3VvjGu
6K3AZLjHMYhDmTY87F9oNG3GWHdsCPufvl+Eq/E21qJ6iEcObMy1vgbGzsF7sgBp
82K4ZxDU4VIRN1rZ3DVoiuJ9/Wn4iNsgP0BQ4yQT3+VdRpfDm8VwuYS0Qydku+N4
Aa5osoJKlGJXCG1XG8H7g8sYFkFD20oQF4Tx+IGFcI5qr8zzWzjN6tnmAmpptyHJ
Aq7FCm3NyNmPLoZVdalYnBtNvCr4VfFMIJuBxB/56Z9Ua4w2Kt/aAY0iQukVR3LN
Q5y5JmvOA8R5ho/uLNXL6GgFR5Kvs3Nd5O3jAjsCAwEAAaNTMFEwHQYDVR0OBBYE
FJ92w2eXVoJHtIQt6uTneszI3DJKMB8GA1UdIwQYMBaAFJ92w2eXVoJHtIQt6uTn
eszI3DJKMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIn/1ab0
9D6/V0mgKXnvgqoG50dpaAmPnLBlIxwaY44OHoYYLzWsTyXa7x6IIRSC5j4J/qGU
Jw8lhwEZzHhaDSgSOAFv/BfjSEYKzI6cFXltPvTwIVyFOiytWMgPaQQkFs8+w7bI
2wZHQV15o/BOEvnb1GNmGOxm2kMXthdafKciKOXq5AxWUiQAZSugXKdYHmt8aCeJ
hqmX76MoU5Mrm/XXKitsqci/sJHLR0eZfw7H/ZbenSWstlKLCZ1Q4GMfjxTKllAs
ORB7+7aqy6gT4qPDDjkMyHMwY4xtMtJQki97su57zhzImQdZgs3BQatymwv7sBJu
F8FdT7DdLg8Wj1M=
-----END CERTIFICATE-----"""
)


def main():
    def ec_certificate():
        certificate = x509.load_der_x509_certificate(EC_CERT_DER)
        print("version", certificate.version)
        print("serial_number", certificate.serial_number)

        print("not_valid_before", certificate.not_valid_before)
        print("not_valid_after", certificate.not_valid_after)

        print("subject", certificate.subject)
        print("issuer", certificate.issuer)

        print("signature_algorithm_oid", certificate.signature_algorithm_oid)
        print("signature_hash_algorithm", certificate.signature_hash_algorithm.name)
        print("signature", certificate.signature)

        print("extensions", certificate.extensions)

        public_key = certificate.public_key()
        public_numbers = public_key.public_numbers()
        print("public_key.curve", public_key.curve.name)
        print("public_key.curve.key_size", public_key.curve.key_size)
        print("public_key.key_size", public_key.key_size)
        public_bytes = certificate.public_bytes()
        print("public_key.public_bytes", public_bytes)
        print("public_key.public_numbers.x", public_numbers.x)
        print("public_key.public_numbers.y", public_numbers.y)
        print(
            "public_key.public_bytes DER",
            certificate.public_bytes(serialization.Encoding.DER),
        )
        print(
            "public_key.public_bytes PEM",
            certificate.public_bytes(serialization.Encoding.PEM).decode(),
        )

        chosen_hash = certificate.signature_hash_algorithm
        digest = hashes.Hash(chosen_hash)
        digest.update(certificate.tbs_certificate_bytes)
        tbs_certificate_hash = digest.finalize()
        public_key.verify(
            certificate.signature,
            tbs_certificate_hash,
            ec.ECDSA(utils.Prehashed(chosen_hash)),
        )

    def rsa_certificate():
        certificate = x509.load_der_x509_certificate(RSA_CERT_DER)
        print("version", certificate.version)
        print("serial_number", certificate.serial_number)

        print("not_valid_before", certificate.not_valid_before)
        print("not_valid_after", certificate.not_valid_after)

        print("subject", certificate.subject)
        print("issuer", certificate.issuer)

        print("signature_algorithm_oid", certificate.signature_algorithm_oid)
        print("signature_hash_algorithm", certificate.signature_hash_algorithm.name)
        print("signature", certificate.signature)

        print("extensions", certificate.extensions)

        public_key = certificate.public_key()
        public_numbers = public_key.public_numbers()

        print("n", public_numbers.n)
        print("e", public_numbers.e)

        print("key_size", public_key.key_size)
        print(
            "public_key.public_bytes DER",
            public_key.public_bytes(serialization.Encoding.DER),
        )
        print(
            "public_key.public_bytes PEM",
            public_key.public_bytes(serialization.Encoding.PEM).decode(),
        )

        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )

    ec_certificate()
    rsa_certificate()


if __name__ == "__main__":
    main()
