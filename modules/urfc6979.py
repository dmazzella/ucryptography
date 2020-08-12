# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
# pylint: disable=no-member
# pylint: disable=no-value-for-parameter
from cryptography import exceptions, hashes, hmac
from cryptography import utils as crypto_util


class RFC6979(object):

    def __init__(self, msg, x, q, hashfunc=hashes.SHA256):
        if hashfunc != hashes.SHA256:
            raise exceptions.UnsupportedAlgorithm()
        self.x = x
        self.q = q
        self.msg = msg
        self.qlen = crypto_util.bit_length(q)
        self.rlen = ((self.qlen + 7) // 8) * 8
        self.hashfunc = hashfunc

    def _bits2int(self, b):
        i = int.from_bytes(b, 'big')
        blen = len(b) * 8
        if blen > self.qlen:
            i >>= (blen - self.qlen)
        return i

    def _int2octets(self, x):
        octets = x.to_bytes((crypto_util.bit_length(x) // 8 + 1), 'big')
        padding = b'\x00' * ((self.rlen // 8) - len(octets))
        return padding + octets

    def _bits2octets(self, b):
        z1 = self._bits2int(b)
        z2 = z1 % self.q
        return self._int2octets(z2)

    def gen_nonce(self):
        algorithm = self.hashfunc()
        h1 = hashes.Hash(algorithm)
        h1.update(self.msg)
        hash_size = algorithm.digest_size
        h1 = h1.finalize()
        key_and_msg = self._int2octets(self.x) + self._bits2octets(h1)
        v = b'\x01' * hash_size
        k = b'\x00' * hash_size
        hmac_context = hmac.HMAC(k, algorithm)
        hmac_context.update(v + b'\x00' + key_and_msg)
        k = hmac_context.finalize()
        hmac_context = hmac.HMAC(k, algorithm)
        hmac_context.update(v)
        v = hmac_context.finalize()
        hmac_context = hmac.HMAC(k, algorithm)
        hmac_context.update(v + b'\x01' + key_and_msg)
        k = hmac_context.finalize()
        hmac_context = hmac.HMAC(k, algorithm)
        hmac_context.update(v)
        v = hmac_context.finalize()

        while True:
            t = b''
            while len(t) * 8 < self.qlen:
                hmac_context = hmac.HMAC(k, algorithm)
                hmac_context.update(v)
                v = hmac_context.finalize()
                t = t + v
            nonce = self._bits2int(t)
            if nonce >= 1 and nonce < self.q:
                return nonce
            hmac_context = hmac.HMAC(k, algorithm)
            hmac_context.update(v + b'\x00')
            k = hmac_context.finalize()
            hmac_context = hmac.HMAC(k, algorithm)
            hmac_context.update(v)
            v = hmac_context.finalize()
