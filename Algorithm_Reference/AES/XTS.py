import AES
import math
import Utils

class XTS:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.valid_Key_Lengths = [32, 64]
        self.key = key
        if (len(self.key) == 32):
            self.key1 = (self.key[0:16]).copy()
            self.key2 = (self.key[16:32]).copy()
        else:
            self.key1 = (self.key[0:32]).copy()
            self.key2 = (self.key[32:64]).copy()

        if (len(self.key) not in self.valid_Key_Lengths):
            raise ValueError("Key is an invalid length, must be in {0}".format(self.valid_Key_Lengths))

    def Encrypt(self, plaintext: bytearray, tweak: bytearray):
        cipherText = bytearray()
        q = 0
        j = 0
        for q in range(0, len(plaintext) - 16, 16):
            input_block = plaintext[q:(q+16)].copy()
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
            j += 1
        if (len(plaintext) > 16):
            q += 16
        # 2 and 3 handled here

        blocks = len(plaintext) // 16 
        b = (len(plaintext) - (blocks * 16)) * 8
        if b == 0:
            print("hi")
            #TODO: fix
            input_block = plaintext[q:(q+16)].copy()
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
        else:
            # m - 1
            input_block = plaintext[q:(q+16)].copy()
            CC = self.EncryptBlock(input_block, tweak, j)
            Cm = Utils.TruncateLeft(Utils.MSB(CC, b))

            # m
            q += 16
            input_block = plaintext[q:].copy()
            CP = Utils.TruncateRight(Utils.LSB(CC, (128 - b)))
            input_block.extend(CP)
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
            cipherText.extend(Cm)
        return cipherText

    def Decrypt(self, cipherText: bytearray, associated_data: bytearray, IV: bytearray, Tag: bytearray):
        H = self.cipher.Decrypt(bytearray([0x00]*16), self.key)

    def EncryptBlock(self, input_block: bytearray, tweak_block: bytearray, j: int):
        # tweak_block = i.to_bytes(16, byteorder="little") // only necessary if the input is I and it is an integer
        T = self.cipher.Encrypt(tweak_block, self.key2)
        T = self.MultiplyA(T, j)
        PP = Utils.xorBlocks(input_block, T)
        CC = self.cipher.Encrypt(PP, self.key1)
        C = Utils.xorBlocks(CC, T)
        return C

    
    #5.2
    def MultiplyA(self, input_block: bytearray, j: int):
        if (len(input_block) != 16):
            raise ValueError("Unable to multiply. input block malformed")
        block = input_block.copy()
        for i in range(0, j):
            new_block = block.copy()
            new_block[0] = (2 * (block[0] % 128)) ^ (135 * math.floor(block[15] / 128))
            for k in range (1,16):
                new_block[k] = (2 * (block[k] % 128) ) ^ (math.floor(block[k-1] / 128))
            block = new_block.copy()
        return block
    


if __name__ == "__main__":
    # from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#XTS

    ## # Key = a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f
    ## # i = 4faef7117cda59c66e4b92013e768ad5
    ## # PT = ebabce95b14d3c8d6fb350390790311c
    ## # CT = 778ae8b43cb98d5a825081d5be471c63
    ## key = [0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,0x76,0x08,0x17,0x62,0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f]
    ## Tweak = [0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,0x6e,0x4b,0x92,0x01,0x3e,0x76,0x8a,0xd5]
    ## Plaintext = [0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,0x6f,0xb3,0x50,0x39,0x07,0x90,0x31,0x1c]
    ## cipher = AES.AES()
    ## AES_XTS = XTS(cipher, 16, key)
    ## ciphertext = AES_XTS.Encrypt(Plaintext, Tweak)
    ## Utils.printByteArray(ciphertext)
    ## # TODO: test Decryption

    # Key = 590ead9adc88682580e3b58171b9d0c52610b5329f551524f021a9ca1dee66dd
    # i = ebe9ba3eb7076efd789fbb905ec49a03
    # PT = 0d5d8dbbbc068bfe0e6de9889abf09283038b38ed5d2796ae738d33a0f3187cb
    # CT = aab7bfce4d6ab3579f60405a0442e17f9cf3256eef3adc30ef9646f0defff6e9
    key = [0x59,0x0e,0xad,0x9a,0xdc,0x88,0x68,0x25,0x80,0xe3,0xb5,0x81,0x71,0xb9,0xd0,0xc5,0x26,0x10,0xb5,0x32,0x9f,0x55,0x15,0x24,0xf0,0x21,0xa9,0xca,0x1d,0xee,0x66,0xdd]
    Tweak = [0xeb,0xe9,0xba,0x3e,0xb7,0x07,0x6e,0xfd,0x78,0x9f,0xbb,0x90,0x5e,0xc4,0x9a,0x03]
    Plaintext = [0x0d,0x5d,0x8d,0xbb,0xbc,0x06,0x8b,0xfe,0x0e,0x6d,0xe9,0x88,0x9a,0xbf,0x09,0x28,0x30,0x38,0xb3,0x8e,0xd5,0xd2,0x79,0x6a,0xe7,0x38,0xd3,0x3a,0x0f,0x31,0x87,0xcb]
    cipher = AES.AES()
    AES_XTS = XTS(cipher, 16, key)
    ciphertext = AES_XTS.Encrypt(Plaintext, Tweak)
    Utils.printByteArray(ciphertext)
    # TODO: test Decryption