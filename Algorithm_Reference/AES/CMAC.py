import AES
import os
import math
import Utils

class CMAC:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key
        self.GenerateSubKeys()
    
    # NIST SP 800-38b #6.1
    def GenerateSubKeys(self):
        #Section 5.3
        R_b = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x87]

        #1
        zero_block = [0x00] * 16
        L = self.cipher.Encrypt(zero_block, self.key)
        #2
        msb_l = L[0] & 0x80

        K1 = Utils.ShiftLeft(L)
        if (msb_l != 0):
            K1 = Utils.xorBlocks(K1, R_b)

        #3
        msb_K1 = K1[0] & 0x80
        K2 = Utils.ShiftLeft(K1)
        if (msb_K1 != 0):
            K2 = Utils.xorBlocks(K2, R_b)

        #4
        self.K1 = K1
        self.K2 = K2

    def Generate(self, message: bytes, TLen: int):
        # 1 completed in init
        # 2
        Mlen = len(message)
        n = 0
        if (Mlen == 0):
            n = 1
        else:
            n = math.ceil(Mlen / self.blockSize)

        #3 & #4
        i = (n - 1) * self.blockSize
        if (Mlen % self.blockSize == 0 and Mlen != 0):
            last_block = bytearray(message[i:(i+self.blockSize)])
            last_block = Utils.xorBlocks(last_block, self.K1)
        else:
            last_block = bytearray(message[i:])
            last_block.append(0x80)
            message.append(0x00)
            while (len(last_block) < 16):
                last_block.append(0x00)
                message.append(0x00)
            last_block = Utils.xorBlocks(last_block, self.K2)
        for j in range(0, self.blockSize):
            message[i + j] = last_block[j]

        #5
        C = bytearray([0x00] * 16)
        #6
        for j in range (0, len(message), 16):
            plaintext_block = bytearray(message[j:(j+16)])
            input_block = Utils.xorBlocks(C, plaintext_block)
            C = self.cipher.Encrypt(input_block, self.key)
        #7
        T = Utils.MSB(C, TLen)
        return T
    
    def Verify(self, message: bytes, T: bytes):
        T_prime = self.Generate(message, len(T) * 8)
        if (T_prime == T):
            return True # Valid
        return False # Invalid

if __name__ == "__main__":
    # works
    # from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
    ## cipher = AES.AES()
    ## key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    ## plaintext = bytearray()
    ## # expected_Tag = BB1D6929 E9593728 7FA37D12 9B756746
    ## aes_CMAC = CMAC(cipher, 16, key)
    ## tag = aes_CMAC.Generate(plaintext, 128)
    ## plaintext = bytearray()
    ## output2 = aes_CMAC.Verify(plaintext, tag)
    ## Utils.printByteArray(tag)
    ## print("isValid: {0}".format(output2))
    ## print()

    # works
    ## cipher = AES.AES()
    ## key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    ## plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a]
    ## # expected_tag = 070A16B4 6B4D4144 F79BDD9D D04A287C
    ## aes_CMAC = CMAC(cipher, 16, key)
    ## tag = aes_CMAC.Generate(plaintext, 128)
    ## plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a]
    ## output2 = aes_CMAC.Verify(plaintext, tag)
    ## printByteArray(tag)
    ## print("isValid: {0}".format(output2))
    ## print()

    # works
    ## cipher = AES.AES()
    ## key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    ## plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a, 0xAE, 0x2D, 0x8A, 0x57]
    ## # expected_tag = 7D85449E A6EA19C8 23A7BF78 837DFADE
    ## aes_CMAC = CMAC(cipher, 16, key)
    ## tag = aes_CMAC.Generate(plaintext, 128)
    ## plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a, 0xAE, 0x2D, 0x8A, 0x57]
    ## output2 = aes_CMAC.Verify(plaintext, tag)
    ## Utils.printByteArray(tag)
    ## print("isValid: {0}".format(output2))
    ## print()
    pass