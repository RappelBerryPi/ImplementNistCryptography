import AES
import Utils

class CTR:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key

    def Encrypt(self, input: bytes, counter: bytes):
        if (len(counter) != self.blockSize):
            raise ValueError("counter must be exactly {0} bytes long".format(self.blockSize))
        
        cipherText = bytearray() 
        for i in range (0,len(input),16):
            output = self.cipher.Encrypt(counter, self.key)
            plaintext_block = bytearray(input[i:(i+16)])
            cipherText_Block = Utils.xorBlocks(plaintext_block, output)
            cipherText.extend(cipherText_Block)
            counter = Utils.increment_counter(counter)
        i += 16
        if (i < len(input)):
            print("x {}".format(i))
            output = self.cipher.Encrypt(counter, self.key)
            plaintext_block = bytearray(input[i:])
            cipherText_Block = Utils.xorBlocks(plaintext_block, output)
            cipherText.extend(cipherText_Block)
        return cipherText 

    def Decrypt(self, input: bytes, counter: bytes):
        # take advantage of the fact that for OFB, we only need the forward cipher
        return self.Encrypt(input, counter)

if __name__ == "__main__":
    # taken from https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf

    cipher = AES.AES()
    key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    counter = [0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff]
    original_counter = [0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff]
    plaintext = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a]
    # expected_Ciphertext = 874d6191b620e3261bef6864990db6ce
    aes_CTR = CTR(cipher, 16, key)
    output = aes_CTR.Encrypt(plaintext, counter)
    counter = original_counter.copy()
    output2 = aes_CTR.Decrypt(output, counter)
    Utils.printByteArray(plaintext)
    Utils.printByteArray(output)
    Utils.printByteArray(output2)