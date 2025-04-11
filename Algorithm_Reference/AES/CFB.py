import AES
import os

class CFB:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key
        self.LSBARRAY = [0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
        self.MSBARRAY = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF]

    def Encrypt(self, input: bytes, IV: bytes, size: int):
        if (len(input) % self.blockSize != 0):
            raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        if (len(IV) != self.blockSize):
            raise ValueError("IV must be exactly {0} bytes long".format(self.blockSize))

        lsb_bits = (self.blockSize*8) - size
        msb_bits = (self.blockSize*8) - lsb_bits
        
        output = bytearray() 
        input_block = IV
        i = 0
        while i < len(input):
            bit_pointer = 0
            plain_textblock = []
            if (i+self.blockSize > len(input)):
                plain_textblock = bytearray(input[i:])
            else:
                plain_textblock = bytearray(input[i:(i+16)])

            output_block = self.cipher.Encrypt(input_block, self.key)
            p_j = self.getNextBits(plain_textblock, bit_pointer, size)
            MSB_j = self.MSB(output_block)
            Cipher_Text_J = self.xorBlocks(p_j, MSB_j)
            output.extend(Cipher_Text_J)


            # TODO: start here and finish. this is becoming harder than expected....
            output_block = self.cipher.Encrypt(input_block, self.key)
            block = bytearray(input[i:(i+16)])
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
            newblock = self.xorBlocks(newblock, IV)
            output.extend(newblock)
            IV = block
        return output

    def xorBlocks(self, block1: bytearray, block2: bytearray):
        for i in range(0, len(block1)):
            block1[i] = block1[i] ^ block2[i]
        return block1

    def LSB(self, byte, s):
        return byte & self.LSBARRAY[s] 

    def MSB(self, byte, s):
        return byte & self.MSBARRAY[s] 


if __name__ == "__main__":
    key = os.urandom(32)
    IV = os.urandom(16)
    cipher = AES.AES()
    input = b'abcdefghijklmnopqrstuvwxyzabcdef'

    aes_cbc = CBC(cipher, 16, key)
    output = aes_cbc.Encrypt(input, IV)
    output2 = aes_cbc.Decrypt(output, IV)
    print(input)
    print(output)
    print(output2)
