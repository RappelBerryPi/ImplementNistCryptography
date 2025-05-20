import os
from Crypto.Cipher import DES
from datetime import datetime

#copied from AES utils
def printByteArray(byteArray: bytearray):
    for o in byteArray:
        print("{0:02x}".format(o),end='')
    print()


key = os.urandom(8)
iv = bytearray([0x00] * 8)
cipher = DES.new(key, DES.MODE_CBC, iv)
plaintext = b'p@ssword'
msg = cipher.encrypt(plaintext)

cipher = DES.new(key, DES.MODE_CBC, iv)
decrypt1 = cipher.decrypt(msg)

print(b"p@ssword" == decrypt1)

key = bytearray([0x00] * 8)
i = 0
start = datetime.now()
for key[0] in range(0, 256, 2):
    for key[1] in range(0, 256, 2):
        for key[2] in range(0, 256, 2):
            for key[3] in range(0, 256, 2):
                print(datetime.now())
                print(key[3])
                print()
                for key[4] in range(0, 256, 2):
                    for key[5] in range(0, 256, 2):
                        for key[6] in range(0, 256, 2):
                            for key[7] in range(0, 256, 2):
                                i += 1
                                cipher = DES.new(key, DES.MODE_ECB)
                                decrypt1 = cipher.decrypt(msg)
                                if (b"p@ssword" == decrypt1):
                                    print("O(n/2): {0:,}".format(2**(56//2)))
                                    print("i:      {0:,}".format(i))
                                    printByteArray(key)
                                    finish = datetime.now()
                                    time_difference = (finish - start).total_seconds
                                    print("Time to brute force key search (optimized): {}".format(time_difference))
                                    exit(0)