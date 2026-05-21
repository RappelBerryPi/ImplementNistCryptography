import AES
import os
from array import array

class CFB:
    def __init__(self, cipher, blockSize, key):
        self.blockSize = blockSize
        self.cipher = cipher
        self.key = key

    def Encrypt(self, input: bytes, IV: bytes, size: int):
        # if (len(input) % self.blockSize != 0):
        #     raise ValueError("length of input must be exactly a multiple of {0}".format(self.blockSize))
        if (len(IV) != self.blockSize):
            raise ValueError("IV must be exactly {0} bytes long".format(self.blockSize))
        if (size not in (1, 8, 64, 128)):
            raise ValueError("size parameter is not correct, must be in 1, 8, 64, or 128")
        
        if (size == 1):
            return self.EncryptCFB1(input, IV)
        
        return self.EncryptCFB(input, IV, size)

    def EncryptCFB1(self, input: bytes, IV: bytes):
        output = array("B")
        input_block_bits = self.convertToBitArray(bytearray(IV))
        input = self.convertToBitArray(bytearray(input))
        for i in range(0, len(input)):
            input_block = self.convertFromBitArray(input_block_bits)
            output_block = self.cipher.Encrypt(input_block, self.key)

            next_bit = input[i]

            # convert output to bitarray
            output_block_bits = self.convertToBitArray(output_block)

            cipherText_j = output_block_bits[0] ^ next_bit

            input_block_bits.pop(0)
            input_block_bits.append(cipherText_j)

            output.append(cipherText_j)

        output = self.convertFromBitArray(output)
        return output

    def EncryptCFB(self, input: bytes, IV: bytes, size: int):
        output = bytearray() 
        size = size // 8 #(put it in byte count)
        input_block = bytearray(IV)
        i = 0
        j = i + size
        input = bytearray(input)
        n = len(input) // size
        while i < n:
            output_block = self.cipher.Encrypt(input_block, self.key)
            next_bytes = input[i:j].copy()
            i = j
            j = i + size

            Cipher_Text_J = self.xorBlocks(next_bytes, output_block[0:size])

            input_block = input_block[size:].copy()
            input_block.extend(Cipher_Text_J)
            output.extend(Cipher_Text_J)
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

    # started from Keccak
    # needed to be modified to match up that a byte should lign up in MSB first and LSB last.
    # i.e. the number 10 is 0x0A and should be represented as 0000_1010 or [0,0,0,0,1,0,1,0]
    # this will be for every byte
    # the easiest way is to do a mask and shift like ConvertBitStringToByteString
    def convertToBitArray(self, text: bytearray) -> array[int]:
        bitArray = array("B") # unsigned bytes, most space efficient
        for i in range(0, len(text)):
            bitArray.extend(self.convertToBits(text[i]))
        return bitArray
    
    # text is 0 < X < 255
    # returns an array of 8 bits
    def convertToBits(self, text: int) -> array[int]:
        returnArray = array("B")
        mask = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
        for i in range(7, -1, -1):
            bit = (text & mask[i]) >> i
            returnArray.append(bit)
        return returnArray
    
    def convertFromBitArray(self, bitArray: array[int]) -> bytearray:
        #sanity check
        if (len(bitArray) % 8 != 0):
            raise ValueError("Something has gone wrong")

        returnArray = bytearray()
        for i in range(0, len(bitArray), 8):
            returnArray.append(self.convertToByte(bitArray[i:(i+8)]))
        return returnArray
    
    # bitArraySlice is an array of 8 bits
    def convertToByte(self, bitArraySlice: array[int]):
        byte = 0
        for i in range(0, 8):
            byte = byte << 1
            byte = byte | bitArraySlice[i]
        return byte

def getBit(string: bytearray, bit_number: int):
    AndFlags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00]
    byte_number = bit_number // 8
    real_bit_number = bit_number - (8 * byte_number)
    return (string[byte_number] & AndFlags[real_bit_number]) >> (real_bit_number)


if __name__ == "__main__":
    # from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    # # Key 2b7e151628aed2a6abf7158809cf4f3c
    # # IV 000102030405060708090a0b0c0d0e0f
    # # Segment #1
    # # Input Block 000102030405060708090a0b0c0d0e0f
    # # Output Block 50fe67cc996d32b6da0937e99bafec60
    # # Plaintext 6b
    # # Ciphertext 3b
    # key = bytearray.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # IV = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    # cipher = AES.AES()
    # input = bytearray.fromhex("6b")
    # aes_cbc = CFB(cipher, 16, key)
    # output = aes_cbc.Encrypt(input, IV, 8)
    # # output2 = aes_cbc.Decrypt(output, IV)
    # print(input.hex())
    # print(output.hex())

    # # Segment #18
    # # Input Block 79424c9c0dd436bace9e0ed4586a4f32
    # # Output Block 946c3dc1584cc18400ecd8c6052c44b1
    # # Plaintext 2d
    # # Ciphertext b9
    # # key = bytearray.fromhex("")
    # # IV = bytearray.fromhex("")
    # cipher = AES.AES()
    # input = bytearray.fromhex("6bc1bee22e409f96e93d7e117393172aae2d")

    # aes_cbc = CFB(cipher, 16, key)
    # output = aes_cbc.Encrypt(input, IV, 8)
    # print(input.hex())
    # print(output.hex())


    # # Segment #1 of F.3.13
    # # Key 2b7e151628aed2a6abf7158809cf4f3c
    # # IV 000102030405060708090a0b0c0d0e0f
    # # Segment #1
    # # Input Block 000102030405060708090a0b0c0d0e0f
    # # Output Block 50fe67cc996d32b6da0937e99bafec60
    # # Plaintext 6bc1bee22e409f96e93d7e117393172a
    # # Ciphertext 3b3fd92eb72dad20333449f8e83cfb4a
    # key = bytearray.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # IV = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    # cipher = AES.AES()
    # input = bytearray.fromhex("6bc1bee22e409f96e93d7e117393172a")

    # aes_cbc = CFB(cipher, 16, key)
    # output = aes_cbc.Encrypt(input, IV, 128)
    # print(input.hex())
    # print(output.hex())

    # #f.3.1
    # key = bytearray.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # IV = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    # cipher = AES.AES()
    # input = bytearray.fromhex("6bc1bee22e409f96e93d7e117393172a")

    # aes_cbc = CFB(cipher, 16, key)
    # output = aes_cbc.Encrypt(input, IV, 1)
    # print(input.hex())
    # print(output.hex())

    ## from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ACVP-AES-CFB1-1.0/internalProjection.json
    ## "tcId": 29,
    ## "payloadLen": 1,
    ## "iv": "C0000000000000000000000000000000",
    ## "pt": "00",
    ## "key": "00000000000000000000000000000000",
    ## "ct": "80"
    #key = bytearray.fromhex("00000000000000000000000000000000")
    #IV = bytearray.fromhex("C0000000000000000000000000000000")
    #cipher = AES.AES()
    #input = bytearray.fromhex("00")

    #aes_cbc = CFB(cipher, 16, key)
    #output = aes_cbc.Encrypt(input, IV, 1) # This is technically correct, but this tests only encrypts and decrypts one single bit... which I'm not going to force my implementation to conform to even though its not much more code
    #print(input.hex()) 
    #print(output.hex())

    # "tcId": 2087,
    # "payloadLen": 8,
    # "iv": "0E9BCCA0A1F1A840D0C9F6FB6FCD4B6E",
    # "pt": "93",
    # "key": "5ACB11FB4A72B089C492D6C8B3636E95",
    # "ct": "75"
    key = bytearray.fromhex("5ACB11FB4A72B089C492D6C8B3636E95")
    IV = bytearray.fromhex("0E9BCCA0A1F1A840D0C9F6FB6FCD4B6E")
    cipher = AES.AES()
    input = bytearray.fromhex("93")

    aes_cbc = CFB(cipher, 16, key)
    output = aes_cbc.Encrypt(input, IV, 1) # This is technically correct, but this tests only encrypts and decrypts one single bit... which I'm not going to force my implementation to conform to even though its not much more code
    print(input.hex()) 
    print(output.hex())


