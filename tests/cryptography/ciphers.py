# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
import random

try:
    from cryptography import ciphers

    Cipher = ciphers.Cipher
    algorithms = ciphers.algorithms
    modes = ciphers.modes
    AESGCM = ciphers.AESGCM
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _flip_last(b):
    # Return a copy of b with its final byte flipped (a minimal tamper).
    a = bytearray(b)
    a[-1] ^= 0x01
    return bytes(a)


def _assert_rejected(label, fn):
    # Security regression guard: a tampered/forged input MUST be rejected.
    # Any exception counts as "rejected"; the failure we care about is a
    # tampered input being silently accepted (fail-open).
    try:
        fn()
    except Exception as ex:
        print("  reject OK:", label, "->", type(ex).__name__)
        return
    raise AssertionError("SECURITY: tampered input accepted -> " + label)


def urandom(size):
    try:
        return bytes(random.getrandbits(8) for i in range(size))
    except ImportError as exc:
        raise exc


def main():
    data = b"a secret message"

    def AES_AESGCM():
        aad = b"\xde\xad\xbe\xef"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"
        # key = AESGCM.generate_key(256)
        # nonce = urandom(12)

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, aad)
        print(ct)
        dt = aesgcm.decrypt(nonce, ct, aad)
        print(dt)

    print("AESGCM")
    AES_AESGCM()

    def AES_GCM():
        aad = b"\xde\xad\xbe\xef"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        nonce = iv = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"
        # key = AESGCM.generate_key(256)
        # nonce = iv = urandom(12)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        print(ct + tag)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag=tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES GCM")
    AES_GCM()

    def AES_GCM_tamper():
        # Guards against AEAD authentication being a no-op: a corrupted tag,
        # ciphertext, AAD or nonce must raise (InvalidTag) and never return
        # plaintext.
        aad = b"\xde\xad\xbe\xef"
        key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
        iv = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"

        # cryptography.Cipher + modes.GCM (tag supplied separately)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        def cipher_decrypt(ct_, tag_, aad_):
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag=tag_)).decryptor()
            decryptor.authenticate_additional_data(aad_)
            return decryptor.update(ct_) + decryptor.finalize()

        assert cipher_decrypt(ct, tag, aad) == data, "GCM round-trip failed"
        _assert_rejected(
            "GCM corrupted tag", lambda: cipher_decrypt(ct, _flip_last(tag), aad)
        )
        _assert_rejected(
            "GCM corrupted ciphertext", lambda: cipher_decrypt(_flip_last(ct), tag, aad)
        )
        _assert_rejected(
            "GCM corrupted AAD", lambda: cipher_decrypt(ct, tag, b"\x00\x00\x00\x00")
        )
        _assert_rejected("GCM truncated tag", lambda: cipher_decrypt(ct, tag[:8], aad))

        # AESGCM one-shot AEAD (tag appended to the ciphertext blob)
        aesgcm = AESGCM(key)
        blob = aesgcm.encrypt(iv, data, aad)
        assert aesgcm.decrypt(iv, blob, aad) == data, "AESGCM round-trip failed"
        _assert_rejected(
            "AESGCM corrupted blob", lambda: aesgcm.decrypt(iv, _flip_last(blob), aad)
        )
        _assert_rejected(
            "AESGCM corrupted AAD",
            lambda: aesgcm.decrypt(iv, blob, b"\x00\x00\x00\x00"),
        )
        _assert_rejected(
            "AESGCM truncated blob", lambda: aesgcm.decrypt(iv, blob[:8], aad)
        )
        _assert_rejected(
            "AESGCM wrong nonce", lambda: aesgcm.decrypt(b"\x00" * 12, blob, aad)
        )
        print("GCM authentication tamper tests passed")

    print("AES GCM tamper")
    AES_GCM_tamper()

    def AES_CBC():
        key = b"g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b"
        iv = b"W/\xa9M\xe4\xa2\x87\xe8\xc0Z\x96D\xd2\xb8\xdd\xc3"
        # key = urandom(32)
        # iv = urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES CBC")
    AES_CBC()

    def AES_ECB():
        key = b"g\xa5\xc2S-\xba\xf87\xe9.\x97xTW+U\xd2\x83a\x81\xef/h\xf3w1\x95\xd26\x16\xc5\x0b"
        # key = urandom(32)

        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("AES ECB")
    AES_ECB()

    def TripleDES_CBC():
        key = b"\xc6\xcf\x90\xb2s\xca\x94\x15]-aDZ\x8b\xe9jT\x068\xec\x9ddi\x9d"
        iv = b"\xf4\xe4l\xd9\x10e\xb3Z"
        # key = urandom(24)
        # iv = urandom(8)

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("3DES CBC")
    TripleDES_CBC()

    def TripleDES_ECB():
        key = b"\xc6\xcf\x90\xb2s\xca\x94\x15]-aDZ\x8b\xe9jT\x068\xec\x9ddi\x9d"
        # key = urandom(24)

        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        print(ct)
        decryptor = cipher.decryptor()
        dt = decryptor.update(ct) + decryptor.finalize()
        print(dt)

    print("3DES ECB")
    TripleDES_ECB()


if __name__ == "__main__":
    main()
