import math
import os
import sys
from cryptography.hazmat.primitives import hashes 

sys.path.append(os.path.abspath("../HMAC/"))

import hmac_impl

def pbkdf2(password: str, salt: str, count: int = 10000, key_length: int = 256, hash: hashes.HashAlgorithm = hashes.SHA3_512()):
    P = password.encode()
    S = bytearray(salt.encode())
    C = count
    kLen = key_length
    hLen = hash.digest_size * 8
    T = list()
    
    if (kLen > (2**32 - 1) * hLen):
        raise Exception("kLen is too long")
    
    length = math.ceil(kLen / hLen)
    r = kLen - ((length - 1) * hLen)

    for i in range(0, length):
        T.append(0)
        U = S + bytearray((i + 1).to_bytes(4, "big"))
        for j in range(0, C):
            U = hmac_impl.hmac(hash, P, U)
            T[i] = T[i] ^ int.from_bytes(U, "big")

    mk = bytearray()

    for i in range(0, len(T)):
        mk.extend(T[i].to_bytes(hash.digest_size, "big"))
    rightTruncate = hLen - r

    while (rightTruncate >= 8):
        mk.pop()
        rightTruncate = rightTruncate - 8
    if (rightTruncate != 0):
        bitMask = (0xff ^ ((0x01 << rightTruncate) - 1))
        mk[-1] = mk[-1] & bitMask
    return mk

#define as bytes because
def pbkdf2_bytes(password: str, salt: str, count: int = 10000, key_length_bytes: int = 32, hash: hashes.HashAlgorithm = hashes.SHA3_512()):
    return pbkdf2(password, salt, count, key_length_bytes * 8, hash)

if __name__ == "__main__":
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    hashing_algorithm = hashes.SHA256()
    password = "hello"
    salt = "world"
    count = 10000
    key_length_bits = 510
    key_length_bytes = key_length_bits // 8

    key1 = bytes(pbkdf2_bytes(password, salt, count, key_length_bytes, hashing_algorithm))

    key2 = PBKDF2HMAC(hashing_algorithm, key_length_bytes, salt.encode(), count).derive(password.encode())

    print("output of my PBKDF2 function:   {}".format(key1))
    print("output of pyca PBKDF2 function: {}".format(key2))
    print("output Keys are equal? {}".format(key1 == key2))