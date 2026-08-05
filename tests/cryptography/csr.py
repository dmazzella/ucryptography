# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import sys

IS_MODULE = sys.implementation.name == "micropython"
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _check(cond, msg):
    if not cond:
        raise AssertionError("FAILED: " + msg)


def _build_csr(key, hash_alg):
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MicroPython"),
            x509.NameAttribute(NameOID.COMMON_NAME, "csr.example"),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.DNSName("csr.example")]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.2.3.4.5.6.7.8"), b"\x13\x05hello"
            ),
            critical=False,
        )
        .sign(key, hash_alg)
    )
    return csr, name


def _check_csr(csr, name):
    _check(csr.is_signature_valid, "csr.is_signature_valid")
    _check(csr.public_key() is not None, "csr.public_key()")
    _check(
        csr.subject.rfc4514_string() == name.rfc4514_string(),
        "csr.subject round-trip",
    )

    der = csr.public_bytes(serialization.Encoding.DER)
    pem = csr.public_bytes(serialization.Encoding.PEM)
    _check(pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"), "PEM header")

    from_der = x509.load_der_x509_csr(der)
    from_pem = x509.load_pem_x509_csr(pem)
    _check(from_der.is_signature_valid, "load_der_x509_csr is_signature_valid")
    _check(from_pem.is_signature_valid, "load_pem_x509_csr is_signature_valid")
    _check(
        from_der.subject.rfc4514_string() == name.rfc4514_string(),
        "load_der subject",
    )
    _check(
        from_pem.public_bytes(serialization.Encoding.DER) == der,
        "load_pem re-encode == der",
    )

    ext = csr.extensions
    bc = ext.get_extension_for_class(x509.BasicConstraints)
    _check(bc.value.ca is False, "BasicConstraints.ca")
    _check(bc.critical is False, "BasicConstraints critical")

    ku = ext.get_extension_for_class(x509.KeyUsage).value
    _check(ku.digital_signature is True, "KeyUsage.digital_signature")
    _check(ku.key_encipherment is True, "KeyUsage.key_encipherment")

    san = ext.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    _check("localhost" in dns and "csr.example" in dns, "SAN DNSName values")

    eku = ext.get_extension_for_class(x509.ExtendedKeyUsage).value
    dotted = [o.dotted_string for o in eku]
    _check("1.3.6.1.5.5.7.3.1" in dotted, "EKU serverAuth")
    _check("1.3.6.1.5.5.7.3.2" in dotted, "EKU clientAuth")

    unrec = ext.get_extension_for_oid(x509.ObjectIdentifier("1.2.3.4.5.6.7.8"))
    _check(unrec.value.value == b"\x13\x05hello", "UnrecognizedExtension value")


def main():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    csr, name = _build_csr(ec_key, hashes.SHA256())
    _check_csr(csr, name)
    print("EC CSR: OK")

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr, name = _build_csr(rsa_key, hashes.SHA384())
    _check_csr(csr, name)
    print("RSA CSR: OK")

    print("ALL CSR TESTS PASSED")


if __name__ == "__main__":
    main()
