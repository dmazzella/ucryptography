# -*- coding: utf-8 -*-
# pylint:disable=import-error
# pylint:disable=no-member
try:
    from cryptography import utils, hashes
except ImportError:
    raise NotImplementedError

if __name__ == "__main__":
    msg = 'sample'
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    q = 0x4000000000000000000020108A2E0CC0D99F8A5EF

    expected = 0x09744429FA741D12DE2BE8316E35E84DB9E5DF1CD
    nonce = utils.RFC6979(msg, x, q, hashes.SHA1()).gen_nonce()
    print(nonce == expected)

    expected = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
    nonce = utils.RFC6979(msg, x, q, hashes.SHA256()).gen_nonce()
    print(nonce == expected)

    expected = 0x2132ABE0ED518487D3E4FA7FD24F8BED1F29CCFCE
    nonce = utils.RFC6979(msg, x, q, hashes.SHA384()).gen_nonce()
    print(nonce == expected)

    expected = 0x00BBCC2F39939388FDFE841892537EC7B1FF33AA3
    nonce = utils.RFC6979(msg, x, q, hashes.SHA512()).gen_nonce()
    print(nonce == expected)
