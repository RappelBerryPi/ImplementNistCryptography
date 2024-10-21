from cryptography.hazmat.primitives.ciphers import algorithms, modes
import base64
import os
# import pdb; pdb.set_trace()
import pdb

key = None
with open('../key.txt') as key_file:
    key = base64.b64decode(key_file.readline())
    pdb.set_trace()

aes = algorithms.AES(key)
mode = modes.GCM(os.urandom(16))
# do more things