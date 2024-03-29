# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
try:
    from cryptography import serialization, hashes, rsa, utils, padding
except ImportError:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import utils
    from cryptography.hazmat.primitives.asymmetric import padding


def rsa_raw_sign(plaintext, private_key):
    d = private_key.private_numbers().d
    n = private_key.public_key().public_numbers().n
    plaintext = (
        bytes([0x00, 0x01])
        + bytes([0xFF] * int(private_key.key_size / 8 - len(plaintext) - 3))
        + bytes([0x00])
        + bytes(plaintext)
    )
    return pow(int.from_bytes(plaintext, "big"), d, n).to_bytes(
        int(private_key.key_size / 8), "big"
    )


def rsa_raw_verify(ciphertext, public_key):
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n
    plaintext = pow(int.from_bytes(ciphertext, "big"), e, n).to_bytes(
        int(public_key.key_size / 8), "big"
    )
    assert plaintext[:2] == bytes([0x00, 0x01])
    return plaintext[plaintext.find(bytes([0x00]), 2) + 1 :]


def main():
    def constructors():
        e = 65537
        n = 20669151410206632564554615344252306337389588258588836590545507045650462512206522333701770111318130920612819909532732844320259029012198321757371548424297248959973354517958168726318424701485035819988142281523433780450682525822300656323934050190090898902195245395944319976919889329950653955989756892251013474118154172102139356464497947910207729771466050967062005127322953249861068239855489809742494784043663371329479155172703116804468392848003281423265931036382175352506852127122629185576186078520227477193661608480063962558426120355247878335805282425854033898449875249558855836276937855796531346036776082939951027361493
        public_numbers = rsa.RSAPublicNumbers(e, n)
        print("n", public_numbers.n)
        print("e", public_numbers.e)
        print("key_size", public_numbers.public_key().key_size)
        print(
            "DER",
            public_numbers.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        print(
            "PEM",
            public_numbers.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode(),
        )

        p = 145851233748249958526948663747245370448044120957101089090351996574378289691101731855026084222931134586040572822263836508163848984179724886978443684864959544656869404925601989890847440781352107279972945068776583392532463684737915624047407193102357057449841174550910168831950564984289963345144552029210640607609
        q = 141713929179941803666289339444699550223015518862109013018930367072211964492039112797820801394889706125808651111772734404801689652729410127517218791875340012660510233315649675030165373681964827215057900409265269718867618510386994121368051878743829851470938426705282253005643995791168016320891012628753174748477
        d = 14206986337116105057227089390917094825524341704451703951879143932212588076771399538676833517014020226449878671051787790684570677325976132569454142573955447669254309794016534577635016517811257893754762124537072516409995815199309972464779546804294134959598230302746597830238037362807072474410952267043523566360796756683867820259467480464185728064662129397413769130427090535290043636733178263124545964575566908414061911782782426610533424991182965550389463780859477530950458019235537378472520713886379437828176754824787371473521551810413344615885535996887124576000078912203641894353557492879049879227043473565294077226721
        dmp1 = 70362977515272577913949919918468298479573538189124694962687627991701151794613172041142556187747588113689134243580202311344987004788293052040793047963370705455181652738647757974562820012878367576649901647001071717071255997686172365007657860816290386886669033000841155499332911379957821857629053839930921831801
        dmq1 = 16083558985617393772523309074105852488804635996404578159433664499185385231118100019686453770773603219002468025227971962447395633565792644284496900590029739142299389892759849899665380616238985379642044390864932422432173375043997471271733064896113743919325572086514326225734776396458606670961248637146438100297
        iqmp = 27479155941606888764196561693435377784782840720640676201668414322119284430835440447305199568634331680003762753130774655317541532510449866672028876124837997900679437646734121402582271170751596331621014149909165652920914546610374838529200728510751855927498562449844460128770756004847015330855240538659537340944
        private_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers)

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

        private_key = private_numbers.private_key()
        print(
            "DER",
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        print(
            "PEM",
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
        )

        chosen_hash = hashes.SHA256()

        message = b"A message I want to sign"
        signature = private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=chosen_hash.digest_size),
            chosen_hash,
        )
        print("PSS signature", signature)

        public_key = private_key.public_key()
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=chosen_hash.digest_size),
            chosen_hash,
        )

        hasher = hashes.Hash(chosen_hash)
        hasher.update(b"data & ")
        hasher.update(b"more data")
        digest = hasher.finalize()
        prehashed_signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(chosen_hash),
                salt_length=chosen_hash.digest_size,
            ),
            utils.Prehashed(chosen_hash),
        )
        print("PSS prehashed_signature", prehashed_signature)

        hasher = hashes.Hash(chosen_hash)
        hasher.update(b"data & ")
        hasher.update(b"more data")
        digest = hasher.finalize()

        public_key.verify(
            prehashed_signature,
            digest,
            padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=chosen_hash.digest_size),
            utils.Prehashed(chosen_hash),
        )

        message = b"A message I want to sign"

        try:
            signature = private_key.sign(
                message,
                None,
                None,
            )
            print("raw signature", signature)

            public_key.verify(
                signature,
                message,
                None,
                None,
            )
        except:
            signature = rsa_raw_sign(message, private_key)
            print("raw signature", signature)

            rsa_raw_verify(signature, public_key)

        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            chosen_hash,
        )
        print("PKCS1v15 signature", signature)

        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            chosen_hash,
        )

        hasher = hashes.Hash(chosen_hash)
        hasher.update(b"data & ")
        hasher.update(b"more data")
        digest = hasher.finalize()
        prehashed_signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(chosen_hash),
        )
        print("PKCS1v15 prehashed_signature", prehashed_signature)

        public_key.verify(
            prehashed_signature,
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(chosen_hash),
        )

        message = b"encrypted data"
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(chosen_hash),
                algorithm=chosen_hash,
                label=None,
            ),
        )
        print("OAEP ciphertext", ciphertext)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(chosen_hash),
                algorithm=chosen_hash,
                label=None,
            ),
        )
        print("OAEP plaintext == message", plaintext == message)

        message = b"encrypted data"
        ciphertext = public_key.encrypt(message, padding.PKCS1v15())
        print("PKCS1v15 ciphertext", ciphertext)

        plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
        print("PKCS1v15 plaintext == message", plaintext == message)

    def generate():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = private_key.public_key().public_numbers()
        print("n", public_numbers.n)
        print("e", public_numbers.e)
        print("key_size", public_numbers.public_key().key_size)
        print(
            "DER",
            public_numbers.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        print(
            "PEM",
            public_numbers.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode(),
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

        print(
            "DER",
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        print(
            "PEM",
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
        )

    constructors()
    generate()


if __name__ == "__main__":
    main()
