# -*- coding: utf-8 -*-
# pylint: disable=import-error
from ubinascii import a2b_base64
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

CERT_DER = b'0\x82\x02\x880\x82\x02/\xa0\x03\x02\x01\x02\x02\x14\x12H}({\x08\x96\xc4y\x9b\xbd\xca\xa0w}vz\x1a\x13\xe10\n\x06\x08*\x86H\xce=\x04\x03\x020\x81\x991\x0b0\t\x06\x03U\x04\x06\x13\x02IT1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05Italy1\x0f0\r\x06\x03U\x04\x07\x0c\x06Napoli1\x160\x14\x06\x03U\x04\n\x0c\rBit4id s.r.l.1\x0c0\n\x06\x03U\x04\x0b\x0c\x03R&D1\x190\x17\x06\x03U\x04\x03\x0c\x10Damiano Mazzella1(0&\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x19damianomazzella@gmail.com0\x1e\x17\r190319133558Z\x17\r200318133558Z0\x81\x991\x0b0\t\x06\x03U\x04\x06\x13\x02IT1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05Italy1\x0f0\r\x06\x03U\x04\x07\x0c\x06Napoli1\x160\x14\x06\x03U\x04\n\x0c\rBit4id s.r.l.1\x0c0\n\x06\x03U\x04\x0b\x0c\x03R&D1\x190\x17\x06\x03U\x04\x03\x0c\x10Damiano Mazzella1(0&\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x19damianomazzella@gmail.com0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04Ag\xc6\\\x9c>_\xd3\xd5\xd9\xcc\xed{\xa4\xb8\xa5pL\xe1\x0b\x8e9\x13K\xe87\x96\x96\xa6\xe7(\xc2\xb5\x97\xbc_\xdf\x03^\xd4fP\xe6\xfb8\xeb^\xf3\xafy\xc2V3\xe1n\xcdj\x08(\xbc7/\xd8N\xa3S0Q0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14ur\xe25{G,\x08\xec\xbfi\x8e\xcf\xe73\x9e\xc8\xf2\xd2\x860\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14ur\xe25{G,\x08\xec\xbfi\x8e\xcf\xe73\x9e\xc8\xf2\xd2\x860\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03G\x000D\x02 f&\xd8\xea\xef\xf7\xbe~\xd0&Y\xb0\xac\xbb\x9d\x87\xf8s\x92~\xc91\n\x93}\xbd\xc2O9\t\x0e\xf5\x02 W].J\xb3\xe2\xe7\xac\xe9\xb4@ZEN\x8dY\xa0\xc4b. \xd5\xbe\xa4\x7f{\x12\x94\x14\xc1z8'

#CERT_DER = load_sequence("../micropython_cmodules/ucryptography/mbed-crypto/tests/data_files/cert_example_multi.crt")

def main():
    certificate = x509.load_der_x509_certificate(CERT_DER)
    print("load_der_x509_certificate: ", certificate)

if __name__ == "__main__":
    main()