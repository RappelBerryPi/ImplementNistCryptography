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
    T = []
    
    if (kLen > (2**32 - 1) * hLen):
        raise Exception("kLen is too long")
    
    len = math.ceil(kLen / hLen)
    r = kLen - ((len - 1) * hLen) # TODO: utilize r

    for i in range(0, len):
        T.append(0)
        U = S + bytearray((i + 1).to_bytes(4, "big"))
        for j in range(0, C):
            U = hmac_impl.hmac(hash, P, U)
            T[i] = T[i] ^ int.from_bytes(U, "big")

    return T[0].to_bytes(int(kLen / 8), "big")

if __name__ == "__main__":
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # hashing_algorithm = hashes.SHA3_512() # TODO: fix for this because of line 29
    hashing_algorithm = hashes.SHA256()
    password = "hello"
    salt = "world"
    count = 10000
    key_length_bits = 256
    key_length_bytes = key_length_bits // 8

    key1 = pbkdf2(password, salt, count, key_length_bits, hashing_algorithm)

    key2 = PBKDF2HMAC(hashing_algorithm, key_length_bytes, salt.encode(), count).derive(password.encode())

    print("output of my PBKDF2 function:   {}".format(key1))
    print("output of pyca PBKDF2 function: {}".format(key2))
    print("output Keys are equal? {}".format(key1 == key2))