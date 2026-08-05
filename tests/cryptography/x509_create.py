# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
try:
    from cryptography import ec, hashes, padding, rsa, serialization, utils, x509

    NameOID = x509.NameOID
    ExtendedKeyUsageOID = x509.ExtendedKeyUsageOID
    IS_MODULE = True
except ImportError:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    IS_MODULE = False

import datetime


def _check(cond, msg):
    if not cond:
        raise AssertionError("FAILED: " + msg)


def _assert_raises(fn, msg):
    try:
        fn()
    except Exception:
        return
    raise AssertionError("expected exception: " + msg)


def _ec_verify(public_key, certificate):
    chosen_hash = certificate.signature_hash_algorithm
    digest = hashes.Hash(chosen_hash)
    digest.update(certificate.tbs_certificate_bytes)
    public_key.verify(
        certificate.signature,
        digest.finalize(),
        ec.ECDSA(utils.Prehashed(chosen_hash)),
    )


def _rsa_verify(public_key, certificate):
    public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


def main():
    def oid_constants():
        _check(
            x509.ObjectIdentifier("1.2.3.4").dotted_string == "1.2.3.4",
            "ObjectIdentifier.dotted_string",
        )
        for const, dotted in (
            (NameOID.COUNTRY_NAME, "2.5.4.6"),
            (NameOID.STATE_OR_PROVINCE_NAME, "2.5.4.8"),
            (NameOID.LOCALITY_NAME, "2.5.4.7"),
            (NameOID.ORGANIZATION_NAME, "2.5.4.10"),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, "2.5.4.11"),
            (NameOID.COMMON_NAME, "2.5.4.3"),
            (NameOID.EMAIL_ADDRESS, "1.2.840.113549.1.9.1"),
            (NameOID.SERIAL_NUMBER, "2.5.4.5"),
            (NameOID.DOMAIN_COMPONENT, "0.9.2342.19200300.100.1.25"),
        ):
            _check(const.dotted_string == dotted, "NameOID " + dotted)
        for const, dotted in (
            (ExtendedKeyUsageOID.SERVER_AUTH, "1.3.6.1.5.5.7.3.1"),
            (ExtendedKeyUsageOID.CLIENT_AUTH, "1.3.6.1.5.5.7.3.2"),
            (ExtendedKeyUsageOID.CODE_SIGNING, "1.3.6.1.5.5.7.3.3"),
            (ExtendedKeyUsageOID.EMAIL_PROTECTION, "1.3.6.1.5.5.7.3.4"),
            (ExtendedKeyUsageOID.TIME_STAMPING, "1.3.6.1.5.5.7.3.8"),
            (ExtendedKeyUsageOID.OCSP_SIGNING, "1.3.6.1.5.5.7.3.9"),
        ):
            _check(const.dotted_string == dotted, "ExtendedKeyUsageOID " + dotted)
        na = x509.NameAttribute(NameOID.COUNTRY_NAME, "IT")
        _check(na.value == "IT", "NameAttribute.value")
        _check(na.oid.dotted_string == "2.5.4.6", "NameAttribute.oid.dotted_string")
        serial = x509.random_serial_number()
        _check(
            isinstance(serial, int) and 0 < serial < (1 << 160),
            "random_serial_number range",
        )
        print("oid_constants OK")

    def ec_full():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Napoli"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MicroPython"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "RnD"),
                x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "a@b.com"),
                x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "example"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, "12345"),
            ]
        )
        serial = x509.random_serial_number()
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

        san_list = [x509.DNSName("localhost"), x509.DNSName("mysite.com")]
        if IS_MODULE:
            san_list.append(x509.IPAddress(b"\x7f\x00\x00\x01"))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2027, 6, 15, 12, 30, 45))
            .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
            .add_extension(
                x509.KeyUsage(True, True, True, True, False, True, True, False, False),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.CODE_SIGNING,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                        ExtendedKeyUsageOID.TIME_STAMPING,
                        ExtendedKeyUsageOID.OCSP_SIGNING,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.2.3.4.5.6.7.8"), b"\x13\x05hello"
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.2.3.4.5.6.7.9"), b"\x04\x03\x01\x02\x03"
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        der = cert.public_bytes(serialization.Encoding.DER)
        pem = cert.public_bytes(serialization.Encoding.PEM)
        _check(der[:1] == b"\x30", "DER starts with SEQUENCE")
        _check(pem.startswith(b"-----BEGIN CERTIFICATE-----"), "PEM header")

        c_der = x509.load_der_x509_certificate(der)
        c = x509.load_pem_x509_certificate(pem)
        _check(c_der.serial_number == serial, "DER serial round-trip")
        _check(c.serial_number == serial, "PEM serial round-trip")
        _check(
            c_der.tbs_certificate_bytes == c.tbs_certificate_bytes,
            "tbs DER == PEM",
        )
        _check(c.signature_hash_algorithm.name == "sha256", "signature_hash sha256")
        _ec_verify(c.public_key(), c)

        # PyCA-like object API: these assertions run on BOTH the module and host PyCA.
        subj_vals = [a.value for a in c.subject]
        for v in (
            "IT",
            "Campania",
            "Napoli",
            "MicroPython",
            "RnD",
            "mysite.com",
            "a@b.com",
            "example",
            "12345",
        ):
            _check(v in subj_vals, "subject value " + repr(v))
        _check(
            c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "mysite.com",
            "subject CN via get_attributes_for_oid",
        )
        ext = c.extensions
        bc = ext.get_extension_for_class(x509.BasicConstraints)
        _check(bc.critical is True, "basic_constraints critical")
        _check(bc.value.ca is True, "basic_constraints ca")
        _check(bc.value.path_length == 2, "basic_constraints path_length")
        ku = ext.get_extension_for_class(x509.KeyUsage).value
        _check(
            ku.digital_signature
            and ku.content_commitment
            and ku.key_encipherment
            and ku.data_encipherment
            and ku.key_cert_sign
            and ku.crl_sign,
            "key_usage flags",
        )
        _check(ku.key_agreement is False, "key_usage key_agreement False")
        ski = ext.get_extension_for_class(x509.SubjectKeyIdentifier).value
        _check(len(ski.digest) == 20, "SKI length")
        aki = ext.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        _check(len(aki.key_identifier) == 20, "AKI length")
        san = ext.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        _check("localhost" in dns, "SAN localhost")
        _check("mysite.com" in dns, "SAN mysite.com")
        eku = ext.get_extension_for_class(x509.ExtendedKeyUsage).value
        _check(len(list(eku)) == 6, "extended_key_usage count")
        u1 = ext.get_extension_for_oid(x509.ObjectIdentifier("1.2.3.4.5.6.7.8"))
        _check(u1.critical is False, "unrecognized non-critical flag")
        _check(u1.value.value == b"\x13\x05hello", "unrecognized non-critical value")
        u2 = ext.get_extension_for_oid(x509.ObjectIdentifier("1.2.3.4.5.6.7.9"))
        _check(u2.critical is True, "unrecognized critical flag")
        _check(u2.value.value == b"\x04\x03\x01\x02\x03", "unrecognized critical value")
        if IS_MODULE:
            _check(c.version == 3, "version 3")
            _check(c.not_valid_before == "2026-01-01 00:00:00", "not_valid_before")
            _check(c.not_valid_after == "2027-06-15 12:30:45", "not_valid_after")
            ips = san.get_values_for_type(x509.IPAddress)
            _check(b"\x7f\x00\x00\x01" in ips, "SAN ip 127.0.0.1")
        print("ec_full OK")

    def rsa_full():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa.example")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2027, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, True, False, False, False, False, False, False
                ),
                critical=True,
            )
            .sign(key, hashes.SHA384())
        )
        c = x509.load_pem_x509_certificate(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        _check(c.signature_hash_algorithm.name == "sha384", "rsa signature_hash sha384")
        _rsa_verify(c.public_key(), c)
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        _check(bc.ca is False, "rsa bc ca False")
        _check(bc.path_length is None, "rsa bc path_length None")
        print("rsa_full OK")

    def ec_ca_and_leaf():
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "My EC CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2036, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.local")])
        leaf = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2027, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("leaf.local")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA512())
        )

        lc = x509.load_pem_x509_certificate(
            leaf.public_bytes(serialization.Encoding.PEM)
        )
        _check(lc.signature_hash_algorithm.name == "sha512", "leaf sha512")
        _ec_verify(ca.public_key(), lc)
        print("ec_ca_and_leaf OK")

    def rsa_ca_and_leaf():
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "My RSA CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2036, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.local")])
        leaf = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2027, 1, 1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        lc = x509.load_pem_x509_certificate(
            leaf.public_bytes(serialization.Encoding.PEM)
        )
        _rsa_verify(ca.public_key(), lc)
        print("rsa_ca_and_leaf OK")

    def hash_algs():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h")])
        algs = [
            (hashes.SHA256(), "sha256"),
            (hashes.SHA384(), "sha384"),
            (hashes.SHA512(), "sha512"),
        ]
        # SHA1 cert signing is allowed by the module/mbedtls but rejected by modern PyCA.
        if IS_MODULE:
            algs.insert(0, (hashes.SHA1(), "sha1"))
        for alg, nm in algs:
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2026, 1, 1))
                .not_valid_after(datetime.datetime(2027, 1, 1))
                .sign(key, alg)
            )
            c = x509.load_der_x509_certificate(
                cert.public_bytes(serialization.Encoding.DER)
            )
            _check(c.signature_hash_algorithm.name == nm, "hash " + nm)
            _ec_verify(c.public_key(), c)
        print("hash_algs OK")

    def negatives():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "n")])
        builder = x509.CertificateBuilder().subject_name(name).issuer_name(name)
        _assert_raises(lambda: builder.sign(key, hashes.SHA256()), "incomplete builder")
        print("negatives OK")

    oid_constants()
    ec_full()
    rsa_full()
    ec_ca_and_leaf()
    rsa_ca_and_leaf()
    hash_algs()
    negatives()
    print("ALL OK")


if __name__ == "__main__":
    main()
