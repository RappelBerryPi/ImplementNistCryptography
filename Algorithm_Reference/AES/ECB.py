import AES
import os
class ECB:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key

    def Encrypt(self, input: bytes):
        if (len(input) % self.blockSize != 0):
            raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        
        output = bytearray() 
        for i in range (0,len(input),16):
            block = input[i:(i+16)]
            block = self.cipher.Encrypt(block, self.key)
            output.extend(block)
        return output

    def Decrypt(self, input: bytes):
        if (len(input) % self.blockSize != 0):
            raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        
        output = bytearray() 
        for i in range (0,len(input),16):
            block = input[i:(i+16)]
            block = self.cipher.Decrypt(block, self.key)
            output.extend(block)
        return output

if __name__ == "__main__":
    key = os.urandom(32)
    cipher = AES.AES()
    input = b'abcdefghijklmnopqrstuvwxyzabcdef'

    aes_ecb = ECB(cipher, 16, key)
    output = aes_ecb.Encrypt(input)
    output2 = aes_ecb.Decrypt(output)
    print(input)
    print(output)
    print(output2)