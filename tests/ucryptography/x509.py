# -*- coding: utf-8 -*-
# pylint: disable=import-error
from ubinascii import a2b_base64
from uio import BytesIO
from cryptography import x509


def loadf_sequence(f):
    f.seek(f.read().index(b'-----BEGIN') or 0)
    l = f.readline()
    if not l.startswith(b'-----BEGIN'):
        # not a pem
        f.seek(0)
        data = f.read()
        if data.startswith(b'\x30'):
            return data
        return a2b_base64(data)

    # pem
    lines = []
    while 1:
        l = f.readline()
        if l == b'' or l.startswith(b'-----END'):
            break
        lines.append(l)
    return a2b_base64(b''.join(lines).replace(b'\n', b''))


def load_sequence(filename):
    f = open(filename, 'rb')
    try:
        return loadf_sequence(f)
    finally:
        f.close()


def loads_sequence(s):
    f = BytesIO(bytes(s, 'utf-8'))
    try:
        return loadf_sequence(f)
    finally:
        f.close()


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
    certificate = x509.load_der_x509_certificate(CERT_DER)
    print("load_der_x509_certificate: ", certificate)


if __name__ == "__main__":
    main()
