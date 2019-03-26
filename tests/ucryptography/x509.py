# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
from uhashlib import sha256
from utime import ticks_us, ticks_diff
from cryptography import x509
try:
    from util import loads_sequence
except ImportError:
    from ucryptography.util import loads_sequence

CERT_DER = loads_sequence('''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----''')


def main():
    start_t = ticks_us()
    certificate = x509.load_der_x509_certificate(CERT_DER)
    print("load_der_x509_certificate: {:6.3f}ms".format(
        ticks_diff(ticks_us(), start_t)/1000))
    print("load_der_x509_certificate: ", certificate)

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
    print("public_key.public_bytes", public_key.public_bytes())
    print("public_key.public_numbers.x", public_numbers.x)
    print("public_key.public_numbers.y", public_numbers.y)

    public_bytes = certificate.public_bytes()
    print("public_key.public_bytes", public_bytes)

    tbs_certificate_hash = sha256(certificate.tbs_certificate_bytes).digest()
    start_t = ticks_us()
    public_key.verify(certificate.signature, tbs_certificate_hash)
    print("verify: {:6.3f}ms".format(ticks_diff(ticks_us(), start_t)/1000))


if __name__ == "__main__":
    main()
