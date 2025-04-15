import AES
import math
import Utils

class GCM:
    def __init__(self, cipher, blockSize, key, Tlen):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key
        # 5.2.1.2
        self.valid_Tag_Lengths = [96, 104, 112, 120, 128]
        self.Tlen = Tlen
        if (self.Tlen not in self.valid_Tag_Lengths):
            raise ValueError("Tag is an invalid length, must be in {0}".format(self.valid_Tag_Lengths))

    def Encrypt(self, plaintext: bytearray, associated_data: bytearray, IV: bytearray):
        if (len(plaintext) * 8) > ((2**39) - 256):
            raise ValueError("plaintext too long")
        if (len(associated_data) * 8) > ((2**64) - 1):
            raise ValueError("associated_data too long")
        if ((len(IV) * 8) > ((2**64) - 1) or len(IV) == 0):
            raise ValueError("IV is an invalid length")
        
        H = self.cipher.Encrypt(bytearray([0x00]*16), self.key)
        J_0 = bytearray()
        if (len(IV) * 8 == 96):
            J_0 = IV.copy()
            J_0.extend([0x00,0x00,0x00,0x01])
        else:
            bit_len_iv = len(IV) * 8
            s = math.ceil(bit_len_iv / 128)
            s = s * 128
            s = s - bit_len_iv
            Ghash_input = IV.copy()
            Ghash_input.extend([0x00] * (len(IV) + (s // 8))) # extend by the proper number of 0 blocks, this is 
            Ghash_input.extend(bit_len_iv.to_bytes(8, byteorder="big"))
            J_0 = self.GHASH(H, Ghash_input)
        C = self.GTR(self.inc32(J_0), plaintext)

        # set u
        bit_len_C = len(C) * 8
        u = math.ceil(bit_len_C / 128)
        u = u * 128
        u = u - bit_len_C

        # set v
        bit_len_A = len(associated_data) * 8
        v = math.ceil(bit_len_A / 128)
        v = v * 128
        v = v - bit_len_A

        Ghash_input = associated_data.copy()
        Ghash_input.extend([0x00] * (v // 8)) # extend by the proper number of 0 blocks, this is 
        Ghash_input.extend(C.copy())
        Ghash_input.extend([0x00] * (u // 8)) # extend by the proper number of 0 blocks, this is 
        Ghash_input.extend(bit_len_A.to_bytes(8, byteorder="big"))
        Ghash_input.extend(bit_len_C.to_bytes(8, byteorder="big"))
        S = self.GHASH(H, Ghash_input)
        T = self.GTR(J_0.copy(), S)
        return C,T

    def Decrypt(self, cipherText: bytearray, associated_data: bytearray, IV: bytearray, Tag: bytearray):
        #1
        if (len(cipherText) * 8) > ((2**39) - 256):
            raise ValueError("ciphertext too long")
        if (len(associated_data) * 8) > ((2**64) - 1):
            raise ValueError("associated_data too long")
        if ((len(IV) * 8) > ((2**64) - 1) or len(IV) == 0):
            raise ValueError("IV is an invalid length")
        if (len(Tag) * 8 != self.Tlen):
            raise ValueError("Tag is an invalid length")

        #2
        H = self.cipher.Encrypt(bytearray([0x00]*16), self.key)

        #3
        J_0 = bytearray()
        if (len(IV) * 8 == 96):
            J_0 = IV.copy()
            J_0.extend([0x00,0x00,0x00,0x01])
        else:
            bit_len_iv = len(IV) * 8
            s = math.ceil(bit_len_iv / 128)
            s = s * 128
            s = s - bit_len_iv
            Ghash_input = IV.copy()
            Ghash_input.extend([0x00] * (len(IV) + (s // 8))) # extend by the proper number of 0 blocks, this is 
            Ghash_input.extend(bit_len_iv.to_bytes(8, byteorder="big"))
            J_0 = self.GHASH(H, Ghash_input)

        # reverse the authentication and the decryption. authentication is #5 -> #8. Decryption is #4.
        # why decrypt and have that in memory before authenticating?
        #5
        # set u
        bit_len_C = len(cipherText) * 8
        u = math.ceil(bit_len_C / 128)
        u = u * 128
        u = u - bit_len_C

        # set v
        bit_len_A = len(associated_data) * 8
        v = math.ceil(bit_len_A / 128)
        v = v * 128
        v = v - bit_len_A

        #6, 7, 8
        Ghash_input = associated_data.copy()
        Ghash_input.extend([0x00] * (v // 8)) # extend by the proper number of 0 blocks, this is 
        Ghash_input.extend(cipherText.copy())
        Ghash_input.extend([0x00] * (u // 8)) # extend by the proper number of 0 blocks, this is 
        Ghash_input.extend(bit_len_A.to_bytes(8, byteorder="big"))
        Ghash_input.extend(bit_len_C.to_bytes(8, byteorder="big"))
        S = self.GHASH(H, Ghash_input)
        T = self.GTR(J_0.copy(), S)
        if (not Utils.isEqual(Tag, T)):
            raise ValueError("Invalid Tag computation")

        #4
        P = self.GTR(self.inc32(J_0), cipherText)
        return P
    
    def inc32(self, IV: bytearray):
        return Utils.increment_counter(IV.copy(), 4)
        
    # 6.3
    def multiplyBlocks(self, X: bytearray, Y: bytearray):
        R = bytearray()
        R.append(0b1110_0001)
        R.extend([0x00] * 15)

        Z = bytearray([0x00] * 16)
        Zero_Array = Z.copy()
        V = Y.copy()
        for i in range (0, 128):
            and_array = (1 << (128 - i - 1)).to_bytes(16, byteorder="big")
            newX = Utils.andBlocks(X, and_array)
            if (not Utils.isEqual(newX, Zero_Array)):
                Z = Utils.xorBlocks(Z, V)
            if (V[15] & 0x01 == 0):
                V = Utils.ShiftRight(V)
            else:
                V = Utils.xorBlocks(Utils.ShiftRight(V), R)
        return Z
    
    # 6.4
    def GHASH(self, H: bytearray, X: bytearray):
        if (len(X) % 16 != 0):
            raise ValueError("X not formatted properly")
        Y = bytearray([0x00] * 16)
        for i in range(0, len(X), 16):
            X_block = X[i:(i+16)].copy()
            U = Utils.xorBlocks(Y.copy(), X_block)
            Y = self.multiplyBlocks(U, H)
        return Y

    # 6.5
    def GTR(self, ICB: bytearray, X: bytearray):
        if (len(X) == 0):
            return X
        n = math.ceil(len(X) / 16)
        CB = ICB.copy()
        cipherText = bytearray()
        for i in range(0, len(X), 16):
            X_block = X[i:(i+16)].copy()
            Y = self.cipher.Encrypt(CB.copy(), self.key)
            Y = Utils.xorBlocks(X_block, Y)
            cipherText.extend(Y)
            CB = self.inc32(CB)
        i += 16
        if (i < len(X)):
            Y = self.cipher.Encrypt(CB, self.key)
            X_block = bytearray(X[i:])
            Y = Utils.xorBlocks(X_block, Y)
            cipherText.extend(Y)
        return cipherText 


if __name__ == "__main__":
    # from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    ## cipher = AES.AES()
    ## # K: FEFFE992 8665731C 6D6A8F94 67308308
    ## # IV: CAFEBABE FACEDBAD DECAF888
    ## # A: 00010203 04050607
    ## # P: 20212223
    ## key = [0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08]
    ## IV = [0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88]
    ## associated_data = []
    ## plaintext = []
    ## Tlen =  128

    ## aes_GCM = GCM(cipher, 16, key, Tlen)
    ## output, Tag = aes_GCM.Encrypt(plaintext, associated_data, IV)
    ## Utils.printByteArray(output)
    ## Utils.printByteArray(Tag)
    ## plaintext2 = aes_GCM.Decrypt(output, associated_data, IV, Tag)
    ## Utils.printByteArrayGrouped(plaintext2)

    cipher = AES.AES()
    # K: FEFFE992 8665731C 6D6A8F94 67308308
    # IV: CAFEBABE FACEDBAD DECAF888
    # A: 00010203 04050607
    # P: 20212223
    key = [0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08]
    IV = [0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88]
    associated_data = []
    plaintext = [0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9A,0x86,0xA7,0xA9,0x53,0x15,0x34,0xF7,0xDA,0x2E,0x4C,0x30,0x3D,0x8A,0x31,0x8A,0x72,0x1C,0x3C,0x0C,0x95,0x95,0x68,0x09,0x53,0x2F,0xCF,0x0E,0x24,0x49,0xA6,0xB5,0x25,0xB1,0x6A,0xED,0xF5,0xAA,0x0D,0xE6,0x57,0xBA,0x63,0x7B,0x39,0x1A,0xAF,0xD2,0x55]
    Tlen =  128

    aes_GCM = GCM(cipher, 16, key, Tlen)
    output, Tag = aes_GCM.Encrypt(plaintext, associated_data, IV)
    Utils.printByteArrayGrouped(output)
    Utils.printByteArrayGrouped(Tag)
    plaintext2 = aes_GCM.Decrypt(output, associated_data, IV, Tag)
    Utils.printByteArrayGrouped(plaintext2)
