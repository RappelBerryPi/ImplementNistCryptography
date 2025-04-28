class SHA3:
    def __init__(self, b):
        self.w = SHA3.permutations_table[b]['w']
        self.b = b
        self.l = SHA3.permutations_table[b]['l']
        self.validHashSizes = [224, 256, 384, 512]
        self.validSHAKESizes = [128, 256]

    permutations_table = {
        25 : {
            'w': 1, 
            'l': 0
        },
        50 : {
            'w': 2, 
            'l': 1
        },
        100 : {
            'w': 4, 
            'l': 2
        },
        200 : {
            'w': 8, 
            'l': 3
        },
        400 : {
            'w': 16, 
            'l': 4
        },
        800 : {
            'w': 32, 
            'l': 5
        },
        1600 : {
            'w': 64, 
            'l': 6
        }
    }

    def SHAKE(self, M, SHAKEsize: int, outputSize: int):
        if (SHAKEsize not in self.validSHAKESizes):
            raise ValueError("size must be a valid size in {}".format(self.validSHAKESizes))
        M = self.convertToBitArray(M)
        M.append(1)
        M.append(1)
        M.append(1)
        M.append(1)
        return self.Keccak_c(SHAKEsize * 2, M, outputSize)

    def Hash(self, M: bytearray, size: int):
        if (size not in self.validHashSizes):
            raise ValueError("size must be a valid size in {}".format(self.validHashSizes))
        M = self.convertToBitArray(M)
        M.append(0)
        M.append(1)
        return self.Keccak_c(size * 2, M, size)

    def Keccak_c(self, c: int, N: list, d: int):
        return self.sponge(self.Keccak_p, 1600, self.pad101, 1600-c, N, d)

    def Keccak_f(self, b: int, S: bytearray):
        l = SHA3.permutations_table[b]['l']
        S = self.convertToBitArray(S)
        return self.Keccak_p(b, 12 + 2 * l, S)

    # Algorithm 7: KECCAK-p[b, nr](S)
    def Keccak_p(self, b: int, nr: int, S: list):
        self.b = b
        self.w = SHA3.permutations_table[b]['w']
        self.l = SHA3.permutations_table[b]['l']
        #1
        A = self.convertStringToStateArray(S)
        # self.printState(A, "before running") #debug
        #2
        start = 12 + 2 * self.l - nr
        end = 12 + 2 * self.l
        # end = 12 + 2 * self.l - nr + 2 #debug
        for round_index in range(start, end):
            A = self.Round(A, round_index)
            # self.printState(A, "after round {0}".format(round_index)) #debug
        #3
        S_prime = self.convertStateArrayToString(A)
        return S_prime
    
    def pad101(self, x: int, m: int):
        j = (-m - 2) % x
        P = [1]
        for _ in range(0, j):
            P.append(0)
        P.append(1)
        return P

    def convertStringToStateArray(self, string: list):
        A = [[[], [], [], [], []], [[], [], [], [], []], [[], [], [], [], []], [[], [], [], [], []], [[], [], [], [], []]]
        for y in range(0, 5):
            for x in range(0, 5):
                for z in range(0, self.w):
                    A[x][y].append(string[self.w * (5 * y + x) + z])
        return A

    def convertStateArrayToString(self, A: list[list[list]]):
        string = []
        for y in range(0, 5):
            for x in range(0, 5):
                for z in range(0, self.w):
                    string.append(A[x][y][z])
        return string

    def convertBitStringToByteString(self, S_prime: list):
        string = bytearray()
        for i in range(0, len(S_prime), 8):
            byte = S_prime[i + 0] << 0
            byte = byte | (S_prime[i + 1] << 1)
            byte = byte | (S_prime[i + 2] << 2)
            byte = byte | (S_prime[i + 3] << 3)
            byte = byte | (S_prime[i + 4] << 4)
            byte = byte | (S_prime[i + 5] << 5)
            byte = byte | (S_prime[i + 6] << 6)
            byte = byte | (S_prime[i + 7] << 7)
            string.append(byte)
        return string
    
    ## # 3.2.1  θ
    def Theta(self, A: list[list[list]]):
        C = [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w] 
        for x in range(0, 5):
            for z in range(0, self.w):
                C[x][z] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]
        D = [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w] 
        for x in range(0, 5):
            a = (x - 1) % 5
            b = (x + 1) % 5
            for z in range(0, self.w):
                c = (z - 1) % self.w
                D[x][z] = C[a][z] ^ C[b][c]
        A_prime = [[[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w]]
        for y in range(0, 5):
            for x in range(0, 5):
                for z in range(0, self.w):
                    A_prime[x][y][z] = A[x][y][z] ^ D[x][z]
        return A_prime
    
    # 3.2.2 ρ
    def Rho(self, A: list[list[list]]):
        A_prime = [[[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w]]

        for z in range(0, self.w):
            A_prime[0][0][z] = A[0][0][z]
        x = 1
        y = 0
        for t in range(0, 24):
            for z in range(0, self.w):
                A_prime[x][y][z] = A[x][y][(z - (((t+1) * (t+2)) // 2)) % self.w]
            old_x = x
            x = y
            y = (2 * old_x + 3 * y) % 5
        return A_prime
    
    #old
    # 3.2.3 π
    def Pi(self, A: list[list[list]]):
        A_prime = [[[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w]]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    A_prime[x][y][z] = A[(x + 3 * y) % 5][x][z]
        return A_prime

    ## # 3.2.3 π
    ## def Pi(self, A: list[list[list]]):
    ##     A_prime = [[[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w]]
    ##     for x_prime in range(0, 5):
    ##         for y_prime in range(0, 5):
    ##             x = y_prime
    ##             y = (2 * x_prime + 3 * y_prime) % 5
    ##             for z in range(0, self.w):
    ##                 A_prime[x][y][z] = A[x_prime][y_prime][z]
    ##     return A_prime

    #3.2.4 χ
    def Chi(self, A: list[list[list]]):
        A_prime = [[[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w], [[0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w, [0] * self.w]]
        for x in range(0, 5):
            for y in range(0, 5):
                for z in range(0, self.w):
                    A_prime[x][y][z] = A[x][y][z] ^ (((A[(x + 1) % 5][y][z]) ^ 1) & (A[(x + 2) % 5][y][z]))
        return A_prime

    #3.2.4 ι
    def Iota(self, A: list[list[list]], round_index: int):
        #1
        A_prime = A.copy()
        #2
        RC = [0] * self.w
        #3
        for j in range(0, self.l + 1):
            RC[(2 ** j) - 1] = self.rc(j + 7 * round_index)
        #4
        # print(RC, round_index) #debug
        for z in range(0, self.w):
            A_prime[0][0][z] = A_prime[0][0][z] ^ RC[z]
        return A_prime
    
    # True False to represent 1 and 0 respectively.
    def rc(self, t: int):
        if (t % 255 == 0):
            return 1
        R = [True, False, False, False, False, False, False, False] # 1 0 0 0 _ 0 0 0 0 
        t = t % 255
        for i in range(0, t):
            #a
            R.insert(0, False)
            #b - e
            R[0] = R[0] ^ R[8]
            R[4] = R[4] ^ R[8]
            R[5] = R[5] ^ R[8]
            R[6] = R[6] ^ R[8]
            #F Trunc8 means to return 0:8. this CAN be done through array slicing, or we can just pop off the last
            R = R[0:8]
        # need to return a bit. This is either 1 or 0. luckily in python byte and boolean can to bitwise operations. so
        # this is effectively 1 & 0 or 1 & 1. 
        return (0x01 & R[0])

    def Round(self, A: list[list[list]], round_index: int):
        intermediate_A = self.Theta(A)
        intermediate_A = self.Rho(intermediate_A)
        intermediate_A = self.Pi(intermediate_A)
        intermediate_A = self.Chi(intermediate_A)
        intermediate_A = self.Iota(intermediate_A, round_index)
        return intermediate_A
    
    def sponge(self, func, func_b: int, pad_func, r: int, N: list, d: int):
        #1
        P = N.copy()
        P.extend(pad_func(r, len(N)))
        #2
        n = len(P) // r
        #3
        c = func_b - r
        # used in 6
        const_c_0 = [0] * (c) 
        #4 
        P_Array = []
        for i in range(0, len(P), r):
            P_i = P[i: (i + r)].copy()
            P_Array.append(P_i)
        #5
        S = [0] * func_b
        #6
        for i in range (0, n):
            P_i = P_Array[i]
            P_i.extend(const_c_0)
            S = xorBlocks(S, P_i)
            S = func(func_b, 24, S)
        #7 & 8 
        Z = S[0:r]
        #9
        if (d <= len(Z)):
            S_prime = Z[0:d].copy()
            returnString = self.convertBitStringToByteString(S_prime)
            return returnString
        while (d > len(Z)):
            # print(d, len(Z)) #debug
            S = func(func_b, 24, S)
            Z.extend(S[0:r])
        S_prime = Z[0:d].copy()
        returnString = self.convertBitStringToByteString(S_prime)
        return returnString
    
    def convertToBitArray(self, Message: bytearray):
        bitArray = []
        for i in range(0, len(Message) * 8):
            bitArray.append(getBit(Message, i))
        return bitArray
    
    def printState(self, A: list[list[list]], message: str = ""):
        print(message)
        for y in range(0, 5):
            print("[",end="")
            for x in range(0,5):
                state_intermediate = self.convertBitStringToByteString(A[x][y])
                num = int.from_bytes(state_intermediate, byteorder="little")
                print(hex(num), end=", ")
                # print(num, end=", ")
            print("]")
        print()

    def printState2(self, A: list[list], message: str = ""):
        print("[",end="")
        for x in range(0, 5):
            state_intermediate = self.convertBitStringToByteString(A[x])
            num = int.from_bytes(state_intermediate, byteorder="little")
            print(hex(num), end=", ")
            # print(num, end=", ")
        print("]")
        print()

#copied from AES Utils.py. Ensure updates go both ways
def xorBlocks(block1: bytearray, block2: bytearray):
    new_block = block1.copy()
    for i in range(0, len(block1)):
        new_block[i] = block1[i] ^ block2[i]
    return new_block 

#copied from AES Utils.py. Ensure updates go both ways
def printByteArray(byteArray: bytearray, end = None):
    for o in byteArray:
        print("{0:02x}".format(o),end='')
    if (end == None):
        print()
    else:
        print(end, end="")

def getBit(string: bytearray, bit_number: int):
    AndFlags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00]
    byte_number = bit_number // 8
    real_bit_number = bit_number - (8 * byte_number)
    return (string[byte_number] & AndFlags[real_bit_number]) >> (real_bit_number)



if __name__ == "__main__":
    # taken from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#sha3vsha3vss
    sha3_instance = SHA3(1600)
    # Len = 8
    # Msg = 01
    # MD = 488286d9d32716e5881ea1ee51f36d3660d70f0db03b3f612ce9eda4
    Digest = bytearray([0x48,0x82,0x86,0xd9,0xd3,0x27,0x16,0xe5,0x88,0x1e,0xa1,0xee,0x51,0xf3,0x6d,0x36,0x60,0xd7,0x0f,0x0d,0xb0,0x3b,0x3f,0x61,0x2c,0xe9,0xed,0xa4])
    Message = bytearray([0x01])
    MessageDigest = sha3_instance.Hash(Message, 224)
    printByteArray(MessageDigest)

    ## sha3_instance = SHA3(1600)
    ## # Len = 128
    ## # Msg = 2bbb42b920b7feb4e3962a1552cc390f
    ## # MD = 0dfa61f6b439bf8e3a6f378fe30a4134e8b2dfb652997a2a76c2789f
    ## Message = bytearray([0x2b,0xbb,0x42,0xb9,0x20,0xb7,0xfe,0xb4,0xe3,0x96,0x2a,0x15,0x52,0xcc,0x39,0x0f])
    ## MessageDigest = sha3_instance.Hash(Message, 224)
    ## printByteArray(MessageDigest)

    import hashlib
    h = hashlib.sha3_224()
    h.update(Message)
    MessageDigest2 = h.digest()
    printByteArray(MessageDigest2)