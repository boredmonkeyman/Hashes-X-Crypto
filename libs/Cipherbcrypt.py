#!/usr/bin/python3
# -*- coding: utf-8 -*-

__all__ = ['algorithmb']

from zlib import compress, decompress
from base64 import b64decode, b64encode

class algorithmb:
    """
    A class containing methods for encoding and decoding data.
    """

    def encd(self, data):
        """
        Encodes data using zlib compression and Base64 encoding.
        """
        zlib_compress = lambda in_: compress(in_)
        base64_encode = lambda in_: b64encode(in_)
        return base64_encode(zlib_compress(data.encode('utf8')))[::-1].decode()

    def decd(self, data):
        """
        Decodes data using Base64 decoding and zlib decompression.
        """
        base64_decode = lambda in_: b64decode(in_)
        zlib_decompress = lambda in_: decompress(in_)
        return zlib_decompress(base64_decode(data[::-1])).decode()
