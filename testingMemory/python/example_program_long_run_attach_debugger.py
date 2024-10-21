from cryptography.hazmat.primitives.ciphers import algorithms, modes
import base64
import os

key = None
with open('../key.txt') as key_file:
    key = base64.b64decode(key_file.readline())

aes = algorithms.AES(key)
mode = modes.GCM(os.urandom(16))
x = input("simulating long running process")
# do more things