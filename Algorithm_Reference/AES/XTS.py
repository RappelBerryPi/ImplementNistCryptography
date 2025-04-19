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

    def Encrypt(self, plaintext: bytearray, tweak: bytearray, length: int = -1):
        # length is an extra parameter to deal with NISTs extra specs in SP 800-38E. IEEE XTS only accepts full bytes,
        # NISTS is a bitstring, so they work in bit lengths that are partial bytes
        cipherText = bytearray()
        q = 0
        j = 0
        for q in range(0, len(plaintext) - 32, 16):
            input_block = plaintext[q:(q+16)].copy()
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
            j += 1
        q = 16 * j
        # 2 and 3 handled here

        blocks = len(plaintext) // 16 
        if (length == -1):
            length = len(plaintext) * 8
        b =  length - (blocks * 16 * 8)
        if b == 0:
            input_block = plaintext[q:(q+16)].copy()
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
            j += 1
            q = 16 * j
            input_block = plaintext[q:(q+16)].copy()
            if (len(input_block) != 0):
                C = self.EncryptBlock(input_block, tweak, j)
                cipherText.extend(C)
        else:
            # m - 1
            input_block = plaintext[q:(q+16)].copy()
            CC = self.EncryptBlock(input_block, tweak, j)
            Cm = Utils.TruncateLeft(Utils.MSB(CC, b), b)
            CP = Utils.LSB(CC, (128 - b))

            # m
            j += 1
            q = 16 * j
            input_block = bytearray([0x00] * 16)
            input_block = Utils.orBlocks(input_block, plaintext[q:].copy())
            input_block = Utils.orBlocks(input_block, CP)
            C = self.EncryptBlock(input_block, tweak, j)
            cipherText.extend(C)
            cipherText.extend(Cm)
        return Utils.TruncateLeft(cipherText, math.ceil(length / 8)) 

    def Decrypt(self, cipherText: bytearray, tweak: bytearray, length = -1):
        # length is an extra parameter to deal with NISTs extra specs in SP 800-38E. IEEE XTS only accepts full bytes,
        # NISTS is a bitstring, so they work in bit lengths that are partial bytes
        plaintext = bytearray()
        q = 0
        j = 0
        for q in range(0, len(cipherText) - 32, 16):
            input_block = cipherText[q:(q+16)].copy()
            P = self.DecryptBlock(input_block, tweak, j)
            plaintext.extend(P)
            j += 1
        q = 16 * j

        blocks = len(cipherText) // 16 
        if (length == -1):
            length = len(cipherText) * 8
        b = length - (blocks * 16 * 8)
        if b == 0:
            input_block = cipherText[q:(q+16)].copy()
            P = self.DecryptBlock(input_block, tweak, j)
            plaintext.extend(P)
            j += 1
            q = 16 * j
            input_block = cipherText[q:(q+16)].copy()
            if (len(input_block) != 0):
                P = self.DecryptBlock(input_block, tweak, j)
                plaintext.extend(P)
        else:
            # m - 1
            input_block = cipherText[q:(q+16)].copy()
            PP = self.DecryptBlock(input_block, tweak, (j + 1))
            MSB_PP = Utils.MSB(PP, b)
            Pm = Utils.TruncateLeft(MSB_PP, b)

            # m
            q += 16
            CP = Utils.LSB(PP, (128 - b))
            input_block = bytearray([0x00] * 16)
            input_block = Utils.orBlocks(input_block, cipherText[q:].copy())
            input_block = Utils.orBlocks(input_block, CP)
            P = self.DecryptBlock(input_block, tweak, j)
            plaintext.extend(P)
            plaintext.extend(Pm)
        return Utils.TruncateLeft(plaintext, math.ceil(length / 8)) 

    def EncryptBlock(self, input_block: bytearray, tweak_block: bytearray, j: int):
        # tweak_block = i.to_bytes(16, byteorder="little") // only necessary if the input is I and it is an integer
        T = self.cipher.Encrypt(tweak_block, self.key2)
        T = self.MultiplyA(T, j)
        PP = Utils.xorBlocks(input_block, T)
        CC = self.cipher.Encrypt(PP, self.key1)
        C = Utils.xorBlocks(CC, T)
        return C
    
    def DecryptBlock(self, input_block: bytearray, tweak_block: bytearray, j: int):
        T = self.cipher.Encrypt(tweak_block, self.key2)
        T = self.MultiplyA(T, j)
        CC = Utils.xorBlocks(input_block, T)
        PP = self.cipher.Decrypt(CC, self.key1) #only difference from above
        P = Utils.xorBlocks(PP, T)
        return P

    
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
    ## p2 = AES_XTS.Decrypt(ciphertext, Tweak)
    ## Utils.printByteArray(ciphertext)
    ## Utils.printByteArray(p2)

    ## # Key = 590ead9adc88682580e3b58171b9d0c52610b5329f551524f021a9ca1dee66dd
    ## # i = ebe9ba3eb7076efd789fbb905ec49a03
    ## # PT = 0d5d8dbbbc068bfe0e6de9889abf09283038b38ed5d2796ae738d33a0f3187cb
    ## # CT = aab7bfce4d6ab3579f60405a0442e17f9cf3256eef3adc30ef9646f0defff6e9
    ## key = [0x59,0x0e,0xad,0x9a,0xdc,0x88,0x68,0x25,0x80,0xe3,0xb5,0x81,0x71,0xb9,0xd0,0xc5,0x26,0x10,0xb5,0x32,0x9f,0x55,0x15,0x24,0xf0,0x21,0xa9,0xca,0x1d,0xee,0x66,0xdd]
    ## Tweak = [0xeb,0xe9,0xba,0x3e,0xb7,0x07,0x6e,0xfd,0x78,0x9f,0xbb,0x90,0x5e,0xc4,0x9a,0x03]
    ## Plaintext = [0x0d,0x5d,0x8d,0xbb,0xbc,0x06,0x8b,0xfe,0x0e,0x6d,0xe9,0x88,0x9a,0xbf,0x09,0x28,0x30,0x38,0xb3,0x8e,0xd5,0xd2,0x79,0x6a,0xe7,0x38,0xd3,0x3a,0x0f,0x31,0x87,0xcb]
    ## cipher = AES.AES()
    ## AES_XTS = XTS(cipher, 16, key)
    ## ciphertext = AES_XTS.Encrypt(Plaintext, Tweak)
    ## p2 = AES_XTS.Decrypt(ciphertext, Tweak)
    ## Utils.printByteArray(ciphertext)
    ## Utils.printByteArray(p2)

    ### not working? (works identical to pyca cryptography. why?)
    ### after doing this with openssl I'm getting the same result which means the vector may not be right?
    ### figured out that the dataunitlength was what was needed. THis isn't in the spec because XTS is meant to run
    ### originally with full bytes, not partial bytes.
    ### COUNT = 210 
    ### DataUnitLen = 130 # the reason why this is failing is because XTS is expecting 130 bits, not 136 bits which was my
    ### assumption. The calculation is correct if it's 136 bits (which is a little frustrating because almost everything
    ### expects full octets. working with count 301 below which gives accurate results.)
    ### Key = 8073f018d40fd8b77eb49a126b5453973620d517ea5b0d4a9d3619cb9869c3ee
    ### i = 756d0270f25bf08f077b7e6223efa137
    ### PT = 59a6d91b83bf8181dfdabfe2b9a9258900
    ### CT = c8b37d8f029b33c645d70dc25f3999cfc0
    ##key = [0x80,0x73,0xf0,0x18,0xd4,0x0f,0xd8,0xb7,0x7e,0xb4,0x9a,0x12,0x6b,0x54,0x53,0x97,0x36,0x20,0xd5,0x17,0xea,0x5b,0x0d,0x4a,0x9d,0x36,0x19,0xcb,0x98,0x69,0xc3,0xee]
    ##Tweak = [0x75,0x6d,0x02,0x70,0xf2,0x5b,0xf0,0x8f,0x07,0x7b,0x7e,0x62,0x23,0xef,0xa1,0x37]
    ##Plaintext = [0x59,0xa6,0xd9,0x1b,0x83,0xbf,0x81,0x81,0xdf,0xda,0xbf,0xe2,0xb9,0xa9,0x25,0x89,0x00] # this is 17 bytes (136 bits)
    ##length = 130

    ##cipher = AES.AES()
    ##AES_XTS = XTS(cipher, 16, key)
    ##ciphertext = AES_XTS.Encrypt(Plaintext, Tweak, length)
    ##p2 = AES_XTS.Decrypt(ciphertext, Tweak, length)
    ##Utils.printByteArray(ciphertext)
    ##Utils.printByteArray(p2)

    ## testing to debug issue with 130 bit length above
    ## from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
    ## AES_pyca = algorithms.AES(bytearray(key))
    ## mode_pyca = modes.XTS(bytearray(Tweak))
    ## cipher = Cipher(AES_pyca, mode_pyca)
    ## e = cipher.encryptor()
    ## ciphertext_pyca = e.update(bytearray(Plaintext)) + e.finalize()
    ## Utils.printByteArray(ciphertext_pyca)
    ## d = cipher.decryptor()
    ## Plaintext_pyca = d.update(ciphertext_pyca) + d.finalize()
    ## Utils.printByteArray(Plaintext_pyca)

    ## # COUNT = 211
    ## # DataUnitLen = 130
    ## # Key = e94364a7da9d6bbacab977198bb1df9524e66dd1c4bce7fcb5ea73840b1afe57
    ## # i = f7a7c30605796429cd752e4781e6d790
    ## # PT = 58e4138743052d0f1140b553b8098e8d80
    ## # CT = f510efc0b7f6dec9015cd6f8facdfed080
    ## key = [0xe9,0x43,0x64,0xa7,0xda,0x9d,0x6b,0xba,0xca,0xb9,0x77,0x19,0x8b,0xb1,0xdf,0x95,0x24,0xe6,0x6d,0xd1,0xc4,0xbc,0xe7,0xfc,0xb5,0xea,0x73,0x84,0x0b,0x1a,0xfe,0x57]
    ## Tweak = [0xf7,0xa7,0xc3,0x06,0x05,0x79,0x64,0x29,0xcd,0x75,0x2e,0x47,0x81,0xe6,0xd7,0x90]
    ## Plaintext = [0x58,0xe4,0x13,0x87,0x43,0x05,0x2d,0x0f,0x11,0x40,0xb5,0x53,0xb8,0x09,0x8e,0x8d,0x80] # this is 17 bytes (136 bits)
    ## cipher = AES.AES()
    ## AES_XTS = XTS(cipher, 16, key)
    ## ciphertext = AES_XTS.Encrypt(Plaintext, Tweak)
    ## p2 = AES_XTS.Decrypt(ciphertext, Tweak)
    ## Utils.printByteArray(ciphertext)
    ## Utils.printByteArray(p2)

    ## COUNT = 301
    ## DataUnitLen = 200
    ## Key = 394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4
    ## i = 4b15c684a152d485fe9937d39b168c29
    ## PT = 2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0
    ## CT = f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e
    pass