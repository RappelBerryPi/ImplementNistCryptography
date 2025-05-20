import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytearray(os.urandom(8))
key2 = key.copy()
key2[0] = key2[0] ^ 0x01 # xor the last bit of each byte of key to double check that it will decrypt to the same value
key2[1] = key2[1] ^ 0x01 
key2[2] = key2[2] ^ 0x01 
key2[3] = key2[3] ^ 0x01 
key2[4] = key2[4] ^ 0x01 
key2[5] = key2[5] ^ 0x01 
key2[6] = key2[6] ^ 0x01 
key2[7] = key2[7] ^ 0x01 

iv = bytearray([0x00] * 8)

cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"p@ssword") + encryptor.finalize()

# for extra trippiness, because we're passing in a zero IV, let's essentially run this completely different key in ECB mode
cipher = Cipher(algorithms.TripleDES(key2), modes.ECB())
decryptor = cipher.decryptor()
decrypt1 = decryptor.update(ct) + decryptor.finalize()
print(b"p@ssword" == decrypt1)