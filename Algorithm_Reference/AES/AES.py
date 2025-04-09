
#rcon Table 5, (pg 17)
rcon = [
    [0x01,0x00,0x00,0x00],
    [0x02,0x00,0x00,0x00],
    [0x04,0x00,0x00,0x00],
    [0x08,0x00,0x00,0x00],
    [0x10,0x00,0x00,0x00],
    [0x20,0x00,0x00,0x00],
    [0x40,0x00,0x00,0x00],
    [0x80,0x00,0x00,0x00],
    [0x1b,0x00,0x00,0x00],
    [0x36,0x00,0x00,0x00]
]

#Table 4 (pg 14)
SBox = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

class AES:
    # rounds isn't passed in in NIST documentation 5.2
    def KeyExpansion(self, key: bytes, rounds):
        i = 0
        words = len(key) // 4 #Nk = length in bytes * 8 (byte -> bit) // word size (32 bits). Since 8 / 32 is equivelent to 1/ 4, just divide by 4.
        w = []
        while i <= words - 1:
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
            i += 1
        while i <= 4 * rounds+ 3:
            temp = w[i-1]
            if (i % words == 0):
                temp = self.XorWords(self.SubWord(self.RotWord(temp)), rcon[(i//words)-1])
            elif (words > 6 and i % words == 4):
                temp = self.SubWord(temp)
            w.append(self.XorWords(w[i-words],temp))
            i += 1
        return w

    def SubWord(self, word):
        returnWord = [SBox[word[0]], SBox[word[1]], SBox[word[2]], SBox[word[3]]]
        return returnWord

    def RotWord(self, word):
        returnWord = [word[1],word[2],word[3],word[0]]
        return returnWord

    def XorWords(self,word1, word2):
        returnWord = [
            word1[0] ^ word2[0],
            word1[1] ^ word2[1],
            word1[2] ^ word2[2],
            word1[3] ^ word2[3],
        ]
        return returnWord

    # FIPS 197 Algorithm 1
    def Cipher(self, input: bytes, rounds: int, w: bytes):
        state = self.convertByteArrayToStateArray(input)
        state = self.AddRoundKey(state, w, 0)
        for round in range (1,rounds):
            state = self.SubBytes(state)
            state = self.ShiftRows(state)
            state = self.MixColumns(state)
            state = self.AddRoundKey(state, w, round)
        state = self.SubBytes(state)
        state = self.ShiftRows(state)
        state = self.AddRoundKey(state, w, rounds)
        return self.convertStateArrayToByteArray(state)
        
    def AES_128(self, input: bytes, key: bytes):
        return self.Cipher(input, 10, self.KeyExpansion(key, 10))

    def AES_192(self, input: bytes, key: bytes):
        return self.Cipher(input, 12, self.KeyExpansion(key, 12))

    def AES_256(self, input: bytes, key: bytes):
        return self.Cipher(input, 14, self.KeyExpansion(key, 14))

    def SubBytes(self, state):
        returnState = [
            [SBox[state[0][0]], SBox[state[0][1]], SBox[state[0][2]], SBox[state[0][3]]],
            [SBox[state[1][0]], SBox[state[1][1]], SBox[state[1][2]], SBox[state[1][3]]],
            [SBox[state[2][0]], SBox[state[2][1]], SBox[state[2][2]], SBox[state[2][3]]],
            [SBox[state[3][0]], SBox[state[3][1]], SBox[state[3][2]], SBox[state[3][3]]]
        ]
        return returnState

    def ShiftRows(self, state):
        returnState = [
            [state[0][0], state[0][1], state[0][2], state[0][3]],
            [state[1][1], state[1][2], state[1][3], state[1][0]],
            [state[2][2], state[2][3], state[2][0], state[2][1]],
            [state[3][3], state[3][0], state[3][1], state[3][2]]
        ]
        return returnState
    
    def MixColumns(self, state):
        returnState = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
        for i in range (0,4):
            returnState[0][i] = self.MULT2(state[0][i]) ^ self.MULT3(state[1][i]) ^ state[2][i] ^ state[3][i]
            returnState[1][i] = self.MULT2(state[1][i]) ^ self.MULT3(state[2][i]) ^ state[3][i] ^ state[0][i]
            returnState[2][i] = self.MULT2(state[2][i]) ^ self.MULT3(state[3][i]) ^ state[0][i] ^ state[1][i]
            returnState[3][i] = self.MULT2(state[3][i]) ^ self.MULT3(state[0][i]) ^ state[1][i] ^ state[2][i]
        return returnState

    def MULT2(self, stateValue):
        if (stateValue & 128 == 0):
            stateValue = (stateValue << 1) % 256
        else:
            stateValue = ((stateValue << 1) % 256) ^ 0b0001_1011
        return stateValue
    
    def MULT3(self, stateValue):
        return self.MULT2(stateValue) ^ stateValue


    def AddRoundKey(self, state, w, round):
        returnState = [
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0]
        ]
        for i in range (0,4):
            word = w[4*round + i]
            returnState[0][i] = state[0][i] ^ word[0]
            returnState[1][i] = state[1][i] ^ word[1]
            returnState[2][i] = state[2][i] ^ word[2]
            returnState[3][i] = state[3][i] ^ word[3]
        return returnState

    # 3.4 of FIPS 197
    def convertByteArrayToStateArray(self, input: bytes):
        if (len(input) != 16):
            raise ValueError("Must be the blocksize of the AES algorithm, which is 16 bytes")
        s = [[input[0], input[4], input[8], input[12]],
             [input[1], input[5], input[9], input[13]],
             [input[2], input[6], input[10], input[14]],
             [input[3], input[7], input[11], input[15]]
            ]
        return s

    def convertStateArrayToByteArray(self, state: bytes):
        outputArray = [state[0][0], state[1][0], state[2][0], state[3][0],
                       state[0][1], state[1][1], state[2][1], state[3][1],
                       state[0][2], state[1][2], state[2][2], state[3][2],
                       state[0][3], state[1][3], state[2][3], state[3][3],
                      ]
        return outputArray              




#
# notes
# hex example
# 57
# 
# multiplicative inverse in GF(2^8)
# BF
# https://tratliff.webspace.wheatoncollege.edu/2016_Fall/math202/inclass/sep21_inclass.pdf (how was BF the right answer?)
# 
# 80 (+) 20 (+) 10 (+) 8 (+) 4 (+) 2 (+) 1
# 38     0e     07     8e    47    ae    57
# 
# 
# 1011 1111
# 
# 7 ^ 3 ^ 4 ^ 5 ^ 6
# 1 ^ 1 ^ 1 ^ 1 ^ 0 = 0
# 
# 
# 6 ^ 2 ^ 3 ^ 4 ^ 5
# 0 ^ 1 ^ 1 ^ 1 ^ 1 = 0
# 
# 5 ^ 1 ^ 2 ^ 3 ^ 4
# 1 ^ 1 ^ 1 ^ 1 ^ 1 = 1


x = AES()

input = [ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
key = [ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ]
returnValue = x.AES_128(input, key)
#expected output is [57, 37, 132, 29, 2, 220, 9, 251, 220, 17, 133, 151, 25, 106, 11, 50]. which it should be.
#Encryption works. Now to do decryption
print(returnValue)

# works

# AES 128
# key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
# expandedKey = x.KeyExpansion(key, 10)
# print(expandedKey)
# for i in range(0, len(expandedKey)):
#     print("{4}: [0x{0:02x}{1:02x}{2:02x}{3:02x}]".format(expandedKey[i][0], expandedKey[i][1], expandedKey[i][2],
#     expandedKey[i][3], i))

# also works

# AES 192
# key = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b]
# expandedKey = x.KeyExpansion(key, 12)
# for i in range(0, len(expandedKey)):
#     print("{4}: [0x{0:02x}{1:02x}{2:02x}{3:02x}]".format(expandedKey[i][0], expandedKey[i][1], expandedKey[i][2], expandedKey[i][3], i))


# also works
#AES 256
# key = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4]
# expandedKey = x.KeyExpansion(key, 14)
# for i in range(0, len(expandedKey)):
#     print("{4}: [0x{0:02x}{1:02x}{2:02x}{3:02x}]".format(expandedKey[i][0], expandedKey[i][1], expandedKey[i][2], expandedKey[i][3], i))