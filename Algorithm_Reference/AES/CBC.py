import AES
import Utils

class CBC:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key

    def Encrypt(self, input: bytes, IV: bytes):
        if (len(input) % self.blockSize != 0):
            raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        if (len(IV) != self.blockSize):
            raise ValueError("IV must be exactly {0} bytes long".format(self.blockSize))
        
        output = bytearray() 
        for i in range (0,len(input),16):
            block = bytearray(input[i:(i+16)])
            block = Utils.xorBlocks(block, IV)
            newblock = self.cipher.Encrypt(block, self.key)
            output.extend(newblock)
            IV = newblock
        return output

    def Decrypt(self, input: bytes, IV: bytes):
        if (len(input) % self.blockSize != 0):
            raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        if (len(IV) != self.blockSize):
            raise ValueError("IV must be exactly {0} bytes long".format(self.blockSize))
        
        output = bytearray() 
        for i in range (0,len(input),16):
            block = bytearray(input[i:(i+16)])
            newblock = self.cipher.Decrypt(block, self.key)
            newblock = Utils.xorBlocks(newblock, IV)
            output.extend(newblock)
            IV = block
        return output


if __name__ == "__main__":
    # works wonderfully
    ## key = os.urandom(32)
    ## IV = os.urandom(16)
    ## cipher = AES.AES()
    ## input = b'abcdefghijklmnopqrstuvwxyzabcdef'

    ## aes_cbc = CBC(cipher, 16, key)
    ## output = aes_cbc.Encrypt(input, IV)
    ## output2 = aes_cbc.Decrypt(output, IV)
    ## print(input)
    ## print(output)
    ## print(output2)

    # test from https://datatracker.ietf.org/doc/html/rfc3602#section-4
    cipher = AES.AES()
    key = [0x06,0xa9,0x21,0x40,0x36,0xb8,0xa1,0x5b,0x51,0x2e,0x03,0xd5,0x34,0x12,0x00,0x06]
    IV = [0x3d,0xaf,0xba,0x42,0x9d,0x9e,0xb4,0x30,0xb4,0x22,0xda,0x80,0x2c,0x9f,0xac,0x41]
    plaintext = b"Single block msg"
    #Expected_Ciphertext =  [0xe3,0x53,0x77,0x9c,0x10,0x79,0xae,0xb8,0x27,0x08,0x94,0x2d,0xbe,0x77,0x18,0x1a]
    aes_cbc = CBC(cipher, 16, key)
    output = aes_cbc.Encrypt(plaintext, IV)
    output2 = aes_cbc.Decrypt(output, IV)
    Utils.printByteArray(plaintext)
    Utils.printByteArray(output)
    Utils.printByteArray(output2)