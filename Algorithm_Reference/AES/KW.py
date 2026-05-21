import AES
import math
import Utils

class KW:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key
        self.semi_blockSize = blockSize // 2
        self.ICV1 = bytearray([0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6])
        self.ICV2 = bytearray([0xA6,0x59,0x59,0xA6])

    def KW_AE(self, plaintext: bytearray):
        S_semi_blocks = math.ceil(len(plaintext) / self.semi_blockSize)
        if (S_semi_blocks < 2 or S_semi_blocks > (2**54) - 1):
            raise ValueError("Unable to encrypt a plaintext with an invalid length")
        S = self.ICV1.copy()
        S.extend(plaintext)
        return self.W(S)

    def KW_AD(self, ciphertext: bytearray):
        S = self.Inv_W(ciphertext)
        Tag = S[0:8]
        if (not Utils.isEqual(self.ICV1, Tag)):
            raise ValueError("FAIL")
        else:
            return S[8:].copy()
        
    def KWP_AE(self, plaintext: bytearray):
        S_semi_blocks = math.ceil(len(plaintext) / self.semi_blockSize)
        if (S_semi_blocks < 1 or S_semi_blocks > (2**32) - 1):
            raise ValueError("Unable to encrypt a plaintext with an invalid length")
        bitlength = len(plaintext) * 8
        bytelen = len(plaintext)
        padlen = 8 * math.ceil(bitlength / 64) - bytelen # after the minus sign is the bitlength / 8. rather than dividing i'll just take the length again
        pad = bytearray([0x00] * padlen)
        S = self.ICV2.copy()
        S.extend(bytelen.to_bytes(4, byteorder="big"))
        S.extend(plaintext.copy())
        S.extend(pad)
        if (bitlength <= 64):
            return self.cipher.Encrypt(S, self.key)
        else:
            return self.W(S)
        
    def KWP_AD(self, ciphertext: bytearray):
        C_semi_blocks = math.ceil(len(ciphertext) / self.semi_blockSize)
        if (C_semi_blocks < 2 or C_semi_blocks > 2**29):
            raise ValueError("Unable to decrypt a ciphertext with an invalid length")
        n = len(ciphertext) // 8
        if len(ciphertext) == 16:
            S = self.cipher.Decrypt(ciphertext, self.key)
        else:
            S = self.Inv_W(ciphertext)
        if (not Utils.isEqual(S[0:4].copy(), self.ICV2)):
            raise ValueError("FAIL")
        plaintext_length = int.from_bytes(S[4:8], byteorder="big")
        pad_length = 8 * (n - 1) - plaintext_length
        if (pad_length < 0 or pad_length > 7):
            raise ValueError("FAIL")
        padding = Utils.TruncateLeft(Utils.LSB(ciphertext, 8 * pad_length), pad_length)
        padding_real = bytearray([0x00] * pad_length)
        if (not Utils.isEqual(padding, padding_real)):
            raise ValueError("FAIL")
        plaintext = Utils.LSB(S, 64 * (n - 1))
        plaintext = Utils.TruncateRight(plaintext)
        plaintext = Utils.MSB(plaintext, 8 * plaintext_length)
        plaintext = Utils.TruncateLeft(plaintext, plaintext_length)
        return plaintext

    def W(self, string: bytearray):
        semi_block_count = len(string) // self.semi_blockSize
        #a
        s = 6 * (semi_block_count - 1)
        A = string[0:self.semi_blockSize].copy()
        #c
        R_i = []
        #d
        for i in range(1, semi_block_count):
            start = (i * self.semi_blockSize)
            finish = start + self.semi_blockSize
            R_i.append(bytearray(string[start: finish]))
        for t in range(1, s + 1):
            old_A = A.copy()
            old_R = R_i.copy() 
            #2A 
            input_block = old_A.copy()
            input_block.extend(old_R[0].copy())
            output_block = self.cipher.Encrypt(input_block, self.key)
            A = Utils.TruncateLeft(Utils.MSB(output_block, 64), 8)
            A = Utils.xorBlocks(A, t.to_bytes(8, byteorder="big"))
            #2B
            for i in range(0, len(R_i) - 1):
                R_i[i] = old_R[i + 1]
            R_i[semi_block_count - 2] = Utils.TruncateRight(Utils.LSB(output_block, 64))
        output = A.copy()
        for i in range(0, len(R_i)):
            output.extend(R_i[i].copy())
        return output

    def Inv_W(self, string: bytearray):
        semi_block_count = len(string) // self.semi_blockSize #n
        #a
        s = 6 * (semi_block_count - 1)
        A = string[0:self.semi_blockSize].copy()
        #c
        R_i = []
        #d
        for i in range(1, semi_block_count):
            start = (i * self.semi_blockSize)
            finish = start + self.semi_blockSize
            R_i.append(bytearray(string[start: finish]))
        for t in range(s, 0, -1):
            old_A = A.copy()
            old_R = R_i.copy() 
            input_block = old_A.copy()
            input_block = Utils.xorBlocks(input_block, t.to_bytes(8, byteorder="big"))
            input_block.extend(R_i[-1].copy())
            output_block = self.cipher.Decrypt(input_block, self.key)
            A = Utils.TruncateLeft(Utils.MSB(output_block, 64), 8)
            R_i[0] = Utils.TruncateRight(Utils.LSB(output_block, 64))
            for i in range(0, len(R_i) - 1):
                R_i[i+1] = old_R[i]
        output = A.copy()
        for i in range(0, len(R_i)):
            output.extend(R_i[i].copy())
        return output

if __name__ == "__main__":
    # from https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#KW

    # pass
    #1 KW_AD_128
    ## cipher = AES.AES()
    ## # COUNT = 0
    ## # K = 1cbd2f79078b9500fae23696311953eb
    ## # C = ecbd7a17c5da3cfdfe2225d2bf9ac7abce78c2b2aefa6eac
    ## # P = 9c4e675277a3bdc3a071048b327a011e
    ## key = [0x1c,0xbd,0x2f,0x79,0x07,0x8b,0x95,0x00,0xfa,0xe2,0x36,0x96,0x31,0x19,0x53,0xeb]
    ## plaintext = [0x9c,0x4e,0x67,0x52,0x77,0xa3,0xbd,0xc3,0xa0,0x71,0x04,0x8b,0x32,0x7a,0x01,0x1e]
    ## ciphertext = [0xec,0xbd,0x7a,0x17,0xc5,0xda,0x3c,0xfd,0xfe,0x22,0x25,0xd2,0xbf,0x9a,0xc7,0xab,0xce,0x78,0xc2,0xb2,0xae,0xfa,0x6e,0xac]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_plaintext = aes_KW.KW_AD(ciphertext)
    ## Utils.printByteArrayGrouped(actual_plaintext)

    ## # pass
    ## #2 KW_AD_128_inv
    ## cipher = AES.AES()
    ## # COUNT = 1
    ## # K = a377331672bf423c0e523d39bb549493
    ## # C = 1f3c7f161fa59b93b3df55ffa092b0e557f92397a0d40159
    ## # FAIL
    ## key = [0xa3,0x77,0x33,0x16,0x72,0xbf,0x42,0x3c,0x0e,0x52,0x3d,0x39,0xbb,0x54,0x94,0x93]
    ## plaintext = []
    ## ciphertext = [0x1f,0x3c,0x7f,0x16,0x1f,0xa5,0x9b,0x93,0xb3,0xdf,0x55,0xff,0xa0,0x92,0xb0,0xe5,0x57,0xf9,0x23,0x97,0xa0,0xd4,0x01,0x59]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_plaintext = aes_KW.KW_AD(ciphertext)
    ## Utils.printByteArrayGrouped(actual_plaintext)

    #3 KW_AE_128
    ## cipher = AES.AES()
    ## # COUNT = 0
    ## # K = 7575da3a93607cc2bfd8cec7aadfd9a6
    ## # P = 42136d3c384a3eeac95a066fd28fed3f
    ## # C = 031f6bd7e61e643df68594816f64caa3f56fabea2548f5fb
    ## key = [0x75,0x75,0xda,0x3a,0x93,0x60,0x7c,0xc2,0xbf,0xd8,0xce,0xc7,0xaa,0xdf,0xd9,0xa6]
    ## plaintext = [0x42,0x13,0x6d,0x3c,0x38,0x4a,0x3e,0xea,0xc9,0x5a,0x06,0x6f,0xd2,0x8f,0xed,0x3f]
    ## ciphertext = [0x03,0x1f,0x6b,0xd7,0xe6,0x1e,0x64,0x3d,0xf6,0x85,0x94,0x81,0x6f,0x64,0xca,0xa3,0xf5,0x6f,0xab,0xea,0x25,0x48,0xf5,0xfb]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_ciphertext = aes_KW.KW_AE(plaintext)
    ## Utils.printByteArrayGrouped(actual_ciphertext)
    ## print(Utils.isEqual(actual_ciphertext, ciphertext))

    #4 KW_AE_128
    ## cipher = AES.AES()
    ## # COUNT = 1
    ## # K = e19be2051ff2627070adf920326ccbbc
    ## # P = e19a9d9368a9e43cf292fec8d959e066
    ## # C = 947ecf0d0b064da737bd7aa92293e2097a1c62c3656c6b8e
    ## key = [0xe1,0x9b,0xe2,0x05,0x1f,0xf2,0x62,0x70,0x70,0xad,0xf9,0x20,0x32,0x6c,0xcb,0xbc]
    ## plaintext = [0xe1,0x9a,0x9d,0x93,0x68,0xa9,0xe4,0x3c,0xf2,0x92,0xfe,0xc8,0xd9,0x59,0xe0,0x66]
    ## ciphertext = [0x94,0x7e,0xcf,0x0d,0x0b,0x06,0x4d,0xa7,0x37,0xbd,0x7a,0xa9,0x22,0x93,0xe2,0x09,0x7a,0x1c,0x62,0xc3,0x65,0x6c,0x6b,0x8e]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_ciphertext = aes_KW.KW_AE(plaintext)
    ## Utils.printByteArrayGrouped(actual_ciphertext)
    ## print(Utils.isEqual(actual_ciphertext, ciphertext))

    #4 KWP_AD_128
    ## cipher = AES.AES()
    ## # COUNT = 0
    ## # K = 49319c331231cd6bf74c2f70b07fcc5c
    ## # C = 9c211f32f8b341f32b052fed5f31a387
    ## # P = e4
    ## key = [0x49,0x31,0x9c,0x33,0x12,0x31,0xcd,0x6b,0xf7,0x4c,0x2f,0x70,0xb0,0x7f,0xcc,0x5c]
    ## plaintext = [0xe4]
    ## ciphertext = [0x9c,0x21,0x1f,0x32,0xf8,0xb3,0x41,0xf3,0x2b,0x05,0x2f,0xed,0x5f,0x31,0xa3,0x87]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_plaintext = aes_KW.KWP_AD(ciphertext)
    ## Utils.printByteArrayGrouped(actual_plaintext)
    ## print(Utils.isEqual(actual_plaintext, plaintext))

    #5 KWP_AD_128
    ## cipher = AES.AES()
    ## # COUNT = 2
    ## # K = 20501013aa1578ab32704a4287029098
    ## # C = 382179a39d75756f57763486d038b50f
    ## # P = 14
    ## key = [0x20,0x50,0x10,0x13,0xaa,0x15,0x78,0xab,0x32,0x70,0x4a,0x42,0x87,0x02,0x90,0x98]
    ## plaintext = [0x14]
    ## ciphertext = [0x38,0x21,0x79,0xa3,0x9d,0x75,0x75,0x6f,0x57,0x76,0x34,0x86,0xd0,0x38,0xb5,0x0f]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_plaintext = aes_KW.KWP_AD(ciphertext)
    ## Utils.printByteArrayGrouped(actual_plaintext)
    ## print(Utils.isEqual(actual_plaintext, plaintext))

    #6 KWP_AD_128
    ## cipher = AES.AES()
    ## # COUNT = 78
    ## # K = e6c203063bf1916eeb463aaf14f55510
    ## # C = 4b7ad717b909c71ecbd4e3ef365b679f215b6b70eb7aa7e6
    ## # P = 380801acd3329adca6
    ## key = [0xe6,0xc2,0x03,0x06,0x3b,0xf1,0x91,0x6e,0xeb,0x46,0x3a,0xaf,0x14,0xf5,0x55,0x10]
    ## plaintext = [0x38,0x08,0x01,0xac,0xd3,0x32,0x9a,0xdc,0xa6]
    ## ciphertext = [0x4b,0x7a,0xd7,0x17,0xb9,0x09,0xc7,0x1e,0xcb,0xd4,0xe3,0xef,0x36,0x5b,0x67,0x9f,0x21,0x5b,0x6b,0x70,0xeb,0x7a,0xa7,0xe6]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_plaintext = aes_KW.KWP_AD(ciphertext)
    ## Utils.printByteArrayGrouped(actual_plaintext)
    ## print(Utils.isEqual(actual_plaintext, plaintext))

    #7 KWP_AE_128
    ## cipher = AES.AES()
    ## # COUNT = 0
    ## # K = 6decf10a1caf8e3b80c7a4be8c9c84e8
    ## # P = 49
    ## # C = 01a7d657fc4a5b216f261cca4d052c2b
    ## key = [0x6d,0xec,0xf1,0x0a,0x1c,0xaf,0x8e,0x3b,0x80,0xc7,0xa4,0xbe,0x8c,0x9c,0x84,0xe8]
    ## plaintext = [0x49]
    ## ciphertext = [0x01,0xa7,0xd6,0x57,0xfc,0x4a,0x5b,0x21,0x6f,0x26,0x1c,0xca,0x4d,0x05,0x2c,0x2b]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_ciphertext = aes_KW.KWP_AE(plaintext)
    ## Utils.printByteArrayGrouped(actual_ciphertext)
    ## print(Utils.isEqual(actual_ciphertext, ciphertext))

    #8 KWP_AE_128
    ## cipher = AES.AES()
    ## # COUNT = 0
    ## # K = 7865e20f3c21659ab4690b629cdf3cc4
    ## # P = bd6843d420378dc896
    ## # C = 41eca956d4aa047eb5cf4efe659661e74db6f8c564e23500
    ## key = [0x78,0x65,0xe2,0x0f,0x3c,0x21,0x65,0x9a,0xb4,0x69,0x0b,0x62,0x9c,0xdf,0x3c,0xc4]
    ## plaintext = [0xbd,0x68,0x43,0xd4,0x20,0x37,0x8d,0xc8,0x96]
    ## ciphertext = [0x41,0xec,0xa9,0x56,0xd4,0xaa,0x04,0x7e,0xb5,0xcf,0x4e,0xfe,0x65,0x96,0x61,0xe7,0x4d,0xb6,0xf8,0xc5,0x64,0xe2,0x35,0x00]

    ## aes_KW = KW(cipher, 16, key)
    ## actual_ciphertext = aes_KW.KWP_AE(plaintext)
    ## Utils.printByteArrayGrouped(actual_ciphertext)
    ## print(Utils.isEqual(actual_ciphertext, ciphertext))
    pass