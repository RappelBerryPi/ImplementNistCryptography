import AES
import Utils

class CCM:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key
        self.valid_Tag_Lengths = [32, 48, 64, 80, 96, 112, 128]

    def Encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes, Tlen: int):
        # formatting requires certain tag lengths
        if (Tlen not in self.valid_Tag_Lengths):
            raise ValueError("TLen must be in {0}".format(self.valid_Tag_Lengths))
        Blocks = self.FormatData(nonce, plaintext, associated_data, Tlen)
        block = bytearray(Blocks[0:16]).copy()
        Y = self.cipher.Encrypt(block, self.key)
        for i in range(16, len(Blocks), 16):
            block = bytearray(Blocks[i:(i+16)]).copy()
            new_block = Utils.xorBlocks(Y, block)
            Y = self.cipher.Encrypt(new_block, self.key)
        # move to later after enciphering it with S_0

        counter = self.SetupCounter(nonce)
        counter_q = 16 - len(nonce) # need for increment counter function. NIST defines as 15-n. I need + 1 more byte
        output = self.cipher.Encrypt(counter, self.key)
        T = Utils.xorBlocks(Y, output)
        T = Utils.MSB(T, Tlen)
        T = Utils.TruncateLeft(T)
        counter = Utils.increment_counter(counter, counter_q)

        ## ctr mode CTR.py
        cipherText = bytearray() 
        for i in range (0,len(plaintext),16):
            output = self.cipher.Encrypt(counter, self.key)
            plaintext_block = bytearray(plaintext[i:(i+16)])
            cipherText_Block = Utils.xorBlocks(plaintext_block, output)
            cipherText.extend(cipherText_Block)
            counter = Utils.increment_counter(counter, counter_q)
        i += 16
        if (i < len(plaintext)):
            output = self.cipher.Encrypt(counter, self.key)
            plaintext_block = bytearray(input[i:])
            cipherText_Block = Utils.xorBlocks(plaintext_block, output)
            cipherText.extend(cipherText_Block)
        cipherText.extend(T)
        return cipherText 

    def Decrypt(self, nonce: bytes, cipherText: bytes, associated_data: bytes, Tlen: int):
        if (Tlen not in self.valid_Tag_Lengths):
            raise ValueError("TLen must be in {0}".format(self.valid_Tag_Lengths))
        if (len(cipherText) <= (Tlen // 8)):
            raise ValueError("Invalid")
        
        counter = self.SetupCounter(nonce)
        counter_q = 16 - len(nonce) # need for increment counter function. NIST defines as 15-n. I need + 1 more byte
        # split out P and T
        P = Utils.MSB(cipherText, (len(cipherText) * 8) - Tlen)
        P = Utils.TruncateLeft(P)
        T = Utils.LSB(cipherText, Tlen)
        T = Utils.TruncateRight(T)

        output = self.cipher.Encrypt(counter, self.key)
        T = Utils.xorBlocks(T, output)
        T = Utils.MSB(T, Tlen)
        T = Utils.TruncateLeft(T)
        counter = Utils.increment_counter(counter, counter_q)

        # TODO: finish
        plaintext = bytearray() 
        for i in range (0,len(P),16):
            output = self.cipher.Encrypt(counter, self.key)
            cipherText_Block = bytearray(P[i:(i+16)])
            plaintext_block = Utils.xorBlocks(cipherText_Block, output)
            plaintext.extend(plaintext_block)
            counter = Utils.increment_counter(counter, counter_q)
        i += 16
        if (i < len(P)):
            output = self.cipher.Encrypt(counter, self.key)
            cipherText_Block = bytearray(P[i:])
            plaintext_block = Utils.xorBlocks(cipherText_Block, output)
            plaintext.extend(plaintext_block)


        Blocks = self.FormatData(nonce, plaintext, associated_data, Tlen)
        block = bytearray(Blocks[0:16]).copy()
        Y = self.cipher.Encrypt(block, self.key)
        for i in range(16, len(Blocks), 16):
            block = bytearray(Blocks[i:(i+16)]).copy()
            new_block = Utils.xorBlocks(Y, block)
            Y = self.cipher.Encrypt(new_block, self.key)
        # move to later after enciphering it with S_0

        T_prime = Utils.MSB(Y, Tlen)
        T_prime = Utils.TruncateLeft(T_prime)
        if (not Utils.isEqual(T, T_prime)):
            raise ValueError("Invalid")
        return plaintext
    
    def FormatData(self, nonce: bytes, plaintext: bytes, associated_data: bytes, Tlen: int):
        #A.2.1
        Bytes = bytearray()
        n = len(nonce)
        a = len(associated_data) 
        p = len(plaintext) 
        t = Tlen // 8
        q = 15 - n

        if (a >= 2**64):
            raise ValueError("Associated Data is too long")
        byte_0_T = ((t - 2) // 2) << 3
        byte_0_q = q - 1
        byte_0 = byte_0_q | byte_0_T
        if (a > 0):
            byte_0 = byte_0 | 0b0100_0000
        Bytes.append(byte_0)
        Bytes.extend(nonce)
        Bytes.extend(bytearray(p.to_bytes(q, byteorder="big")))

        # TODO: run sanity check here to make sure that the data is 16 bytes long at this point
        #A.2.2
        if (a > 0 and a < (2**16-2**8)):
            Bytes.extend(bytearray(a.to_bytes(2, byteorder="big")))
        elif (a >= (2**16-2**8) and a < 2**32):
            Bytes.extend(bytearray([0xff, 0xfe]))
            Bytes.extend(a.to_bytes(4, byteorder="big"))
        else:
            Bytes.extend(bytearray([0xff, 0xff]))
            Bytes.extend(a.to_bytes(8, byteorder="big"))

        Bytes.extend(associated_data)

        while len(Bytes) % 16 != 0:
            Bytes.append(0x00)

        self.u = len(Bytes) // 16 # TODO: setting as a property. right thing to do? maybe
        
        Bytes.extend(plaintext)

        while len(Bytes) % 16 != 0:
            Bytes.append(0x00)

        self.r = len(Bytes) // 16 # TODO: setting as a property. right thing to do? maybe

        return Bytes
    
    def SetupCounter(self, nonce: bytearray):
        counter = bytearray()
        counter.append(15 - len(nonce) - 1) # flags = reserved | reserved | 0 | 0 | 0 | q-1
        counter.extend(nonce)
        while (len(counter) % 16 != 0):
            counter.append(0x00)
        return counter


if __name__ == "__main__":
    # test from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    ## cipher = AES.AES()
    ## # K: 40414243 44454647 48494a4b 4c4d4e4f
    ## # N: 10111213 141516
    ## # A: 00010203 04050607
    ## # P: 20212223
    ## key = [0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f]
    ## nonce = [0x10,0x11,0x12,0x13,0x14,0x15,0x16]
    ## associated_data = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07]
    ## plaintext = [0x20,0x21,0x22,0x23]
    ## Tlen = 32 

    ## aes_CCM = CCM(cipher, 16, key)
    ## output = aes_CCM.Encrypt(nonce, plaintext, associated_data, Tlen)
    ## # associated_data[0] = 0x0f # validate that it throws an error
    ## # output[0] = 0x0f # validate that it throws an error
    ## output2 = aes_CCM.Decrypt(nonce, output, associated_data ,Tlen)
    ## #Utils.printByteArray(plaintext)
    ## Utils.printByteArray(output)
    ## Utils.printByteArray(output2)

    # test from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    ## cipher = AES.AES()
    ## # K: 40414243 44454647 48494a4b 4c4d4e4f
    ## # N: 10111213 14151617
    ## # A: 00010203 04050607 08090a0b 0c0d0e0f
    ## # P: 20212223 24252627 28292a2b 2c2d2e2f
    ## key = [0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f]
    ## nonce = [0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17]
    ## associated_data = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]
    ## plaintext = [0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f]
    ## Tlen = 48

    ## aes_CCM = CCM(cipher, 16, key)
    ## output = aes_CCM.Encrypt(nonce, plaintext, associated_data, Tlen)
    ## # associated_data[0] = 0x0f # validate that it throws an error
    ## output2 = aes_CCM.Decrypt(nonce, output, associated_data ,Tlen)
    ## Utils.printByteArrayGrouped(output)
    ## Utils.printByteArray(output2)

    # test from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    ## cipher = AES.AES()
    ## # K: 40414243 44454647 48494a4b 4c4d4e4f
    ## # N: 10111213 14151617 18191a1b
    ## # A: 00010203 04050607 08090a0b 0c0d0e0f 10111213
    ## # P: 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637
    ## key = [0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f]
    ## nonce = [0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b]
    ## associated_data = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13]
    ## plaintext = [0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37]
    ## Tlen = 64

    ## aes_CCM = CCM(cipher, 16, key)
    ## output = aes_CCM.Encrypt(nonce, plaintext, associated_data, Tlen)
    ## # associated_data[0] = 0x0f # validate that it throws an error
    ## output2 = aes_CCM.Decrypt(nonce, output, associated_data ,Tlen)
    ## Utils.printByteArrayGrouped(output)
    ## Utils.printByteArray(output2)
    pass