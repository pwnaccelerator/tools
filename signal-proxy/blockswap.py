#!/usr/bin/env python

# python2

from Crypto.Cipher import AES
from binascii import hexlify as hexa
from os import urandom

BLOCKLEN = 16

def blocks(data):
    split = [hexa(data[i:i+BLOCKLEN]) for i in range(0, len(data), BLOCKLEN)]
    return ' '.join(split)


def xorblocks(b1, b2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(b1, b2))


# pick a random key
k = urandom(16)
print("k = %s" % hexa(k))

# pick a random IV
iv = urandom(16)
print("iv = %s\n" % hexa(iv))

# pick an instance of AES in CBC mode
aes = AES.new(k, AES.MODE_CBC, iv)
p = '\x00'*BLOCKLEN + '\x41'*BLOCKLEN + '\xff'*BLOCKLEN
c = aes.encrypt(p)
print("enc:\n%s\n->\n%s\n" % (blocks(p), blocks(c)))

aes = AES.new(k, AES.MODE_CBC, iv)
cc = c + c + c
pp = aes.decrypt(cc)
print("dec:\n%s\n->\n%s\n" % (blocks(cc), blocks(pp)))

aes = AES.new(k, AES.MODE_CBC, iv)
cc = c + xorblocks(c[:16], '\x01'*16) + c[16:32] + xorblocks(iv,
    '\xee'*16) + c[:16] + xorblocks(c[16:32], '\xaa'*16) + c[32:]
pp = aes.decrypt(cc)
print("dec:\n%s\n->\n%s" % (blocks(cc), blocks(pp)))
