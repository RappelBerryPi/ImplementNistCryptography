import AES
import os

class OFB:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key

    def Encrypt(self, input: bytes, IV: bytes):
        if (len(IV) != self.blockSize):
            raise ValueError("IV must be exactly {0} bytes long".format(self.blockSize))
        
        cipherText = bytearray() 
        input_block = IV
        for i in range (0,len(input),16):
            output = self.cipher.Encrypt(input_block, self.key)
            plaintext_block = bytearray(input[i:(i+16)])
            cipherText_Block = self.xorBlocks(plaintext_block, output)
            input_block = output
            cipherText.extend(cipherText_Block)
        i += 16
        if (i < len(input)):
            output = self.cipher.Encrypt(input_block, self.key)
            plaintext_block = bytearray(input[i:])
            cipherText_Block = self.xorBlocks(plaintext_block, output)
            cipherText.extend(cipherText_Block)
        return cipherText 

    def Decrypt(self, input: bytes, IV: bytes):
        # take advantage of the fact that for OFB, we only need the forward cipher
        return self.Encrypt(input, IV)

    def xorBlocks(self, block1: bytearray, block2: bytearray):
        for i in range(0, len(block1)):
            block1[i] = block1[i] ^ block2[i]
        return block1

if __name__ == "__main__":
    # works
    # taken from https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
    ## cipher = AES.AES()
    ## key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    ## IV = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F]
    ## plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a, 0x6b]
    ## # expected_Ciphertext = 3b3fd92eb72dad20333449f8e83cfb4a
    ## aes_OFB = OFB(cipher, 16, key)
    ## output = aes_OFB.Encrypt(plaintext, IV)
    ## output2 = aes_OFB.Decrypt(output, IV)
    ## for o in plaintext:
    ##     print("{0:02x}".format(o),end='')
    ## print()
    ## for o in output:
    ##     print("{0:02x}".format(o),end='')
    ## print()
    ## for o in output2:
    ##     print("{0:02x}".format(o),end='')
    ## print()


    # from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers (mmt -> OFBMMT128.rsp)
    cipher = AES.AES()
    key = [0xc9,0xf4,0xce,0x21,0xb4,0xc7,0xda,0xaa,0x4f,0x93,0xe2,0x92,0xdc,0x60,0x5b,0xc5]
    IV = [0x5e,0x5a,0x8c,0xf2,0x80,0x8c,0x72,0x0e,0x01,0xc1,0xed,0x92,0xd4,0x70,0xa4,0x5d]
    plaintext = [0x8e,0x19,0xc5,0xca,0xcd,0x01,0x5a,0x66,0x2e,0x7f,0x40,0xcd,0xec,0xad,0xbf,0x79,0xa6,0x80,0x81,0xc0,0x6d,0x95,0x44,0xb4,0x1c,0x2d,0xd2,0x48,0xe7,0x76,0x33,0xb4]
    # expected_ciphertext = 885dc48add7ee6a1839bc5c5e03beae071301ecf91a0111520cde0d3a112f5d2

    aes_OFB = OFB(cipher, 16, key)
    output = aes_OFB.Encrypt(plaintext, IV)
    output2 = aes_OFB.Decrypt(output, IV)
    for o in plaintext:
        print("{0:02x}".format(o),end='')
    print()
    for o in output:
        print("{0:02x}".format(o),end='')
    print()
    for o in output2:
        print("{0:02x}".format(o),end='')
    print()