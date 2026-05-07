from enum import Enum
sys.path.append("../")
import SHA3.IncrementalSHAKE
import SHA3.SHA_3

class ML_KEM_PARAMETER_SET:
    ML_KEM_512 = 1
    ML_KEM_768 = 2
    ML_KEM_1024 = 3

class ML_KEM:

    _MLKEM_dictionary = {
        ML_KEM_PARAMETER_SET.ML_KEM_512: {
            "n": 256,
            "q": 3329,
            "k": 2,
            "Nu1": 3,
            "Nu2": 2,
            "d_u": 10,
            "d_v": 4,
            "requiredRBG": 128
        },
        ML_KEM_PARAMETER_SET.ML_KEM_768: {
            "n": 256,
            "q": 3329,
            "k": 3,
            "Nu1": 2,
            "Nu2": 2,
            "d_u": 10,
            "d_v": 4,
            "requiredRBG": 192
        },
        ML_KEM_PARAMETER_SET.ML_KEM_512: {
            "n": 256,
            "q": 3329,
            "k": 4,
            "Nu1": 2,
            "Nu2": 2,
            "d_u": 11,
            "d_v": 5,
            "requiredRBG": 256
        }
    }



    # constants from section 2.3... all capitalized because programming constants should be capitals
    ZETA = 17

    # Constants from Appendix A to save on computation

    # used in ALG 9 and 10 instead of pow(ZETA, bitrev7(i), Q)
    ZETA_ARRAY = [1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154]

    # used in ALG 11 instead of pow(ZETA, 2bitrev7(i) + 1, Q)
    ZETA_PLUS1_ARRAY = [17, -17, 2761, -2761, 583, -583, 2649, -2649, 1637, -1637, 723, -723, 2288, -2288, 1100, -1100, 1409, -1409, 2662, -2662, 3281, -3281, 233, -233, 756, -756, 2156, -2156, 3015, -3015, 3050, -3050, 1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952, -952, 1461, -1461, 2687, -2687, 939, -939, 2308, -2308, 2437, -2437, 2388, -2388, 733, -733, 2337, -2337, 268, -268, 641, -641, 1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, 375, -375, 2549, -2549, 2090, -2090, 1645, -1645, 1063, -1063, 319, -319, 2773, -2773, 757, -757, 2099, -2099, 561, -561, 2466, -2466, 2594, -2594, 2804, -2804, 1092, -1092, 403, -403, 1026, -1026, 1143, -1143, 2150, -2150, 2775, -2775, 886, -886, 1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029, 2110, -2110, 2935, -2935, 885, -885, 2154, -2154]

    def __init__(self, parameterSet: ML_KEM_PARAMETER_SET):
        self.n = self._MLKEM_dictionary[parameterSet]["n"]
        self.q = self._MLKEM_dictionary[parameterSet]["q"]
        self.k = self._MLKEM_dictionary[parameterSet]["k"]
        self.Nu1 = self._MLKEM_dictionary[parameterSet]["Nu1"]
        self.Nu2 = self._MLKEM_dictionary[parameterSet]["Nu2"]
        self.d_u = self._MLKEM_dictionary[parameterSet]["d_u"]
        self.d_u = self._MLKEM_dictionary[parameterSet]["d_u"]
        self.d_v = self._MLKEM_dictionary[parameterSet]["d_v"]
        self.requiredRBGSize = self._MLKEM_dictionary[parameterSet]["requiredRBG"]


    #4.2
    # Algorithm 3
    # copied from Keccak
    def BitsToBytes(self, bit_array: list[bool]):
        string = bytearray()
        for i in range(0, len(bit_array), 8):
            byte = bit_array[i + 0] << 0
            byte = byte | (bit_array[i + 1] << 1)
            byte = byte | (bit_array[i + 2] << 2)
            byte = byte | (bit_array[i + 3] << 3)
            byte = byte | (bit_array[i + 4] << 4)
            byte = byte | (bit_array[i + 5] << 5)
            byte = byte | (bit_array[i + 6] << 6)
            byte = byte | (bit_array[i + 7] << 7)
            string.append(byte)
        return string

    # Algorithm 4
    # copied from Keccak
    # this seems to be more efficient (without actually testing it) than real algorithm 4. Which is a valid way of
    # achieving the same result.
    def BytesToBits(self, Message: bytearray):
        bitArray = []
        for i in range(0, len(Message) * 8):
            bitArray.append(getBit(Message, i))
        return bitArray

    # Algorithm 5
    # Note here. the definition of F says that it is an array of numbers belonging to the set of all integers (bold face
    # Z) moduluo the number m (the subscript).
    # the superscript (256) is a little bit more complicated to explain. It's the Cartesian Square of all integers
    # modulo m. so this is a complete set of individual variables in the array, that are all within that boundary.
    # so when you have Z (superscript) 256, this is a set x_1, and a set x_2, and a set x_3, and a set .... x_256 that
    # are all uniquely belong to the set Z(mod m). so x_1 belongs to (∈ <- that symbol) Z(mod m) , and x_2 belongs to Z
    # (mod m), and .... so on so forth.
    # to put it into laymans terms:
    # +  This is a 256 integer array, of numbers ranging from 0 to m.
    # +  m has to be 2 to the "dth" power, and d has to be between 1 and 12. 
    def ByteEncode(self, F: bytearray, d: int):
        b = list[]
        m = 2**d # TODO: check if m need to be implemented
        for i in range (0, 256):
            a = F[i]
            # this operation essentially encodes each integer into a bit array in reverse order.
            # so the number 10 in binary would be "0b1010" 
            # this would encode it so the array ends up being b = [0, 1, 0, 1]
            # same for 128, in binary it's "0b1000 0000".
            # the array would end up encoded as b = [0, 0, 0, 0, 0, 0, 0, 1]
            for j in range(0, d):
                b[i * d + j] = bool(a % 2)
                a = (a - int(b[i * d + j])) / 2
        B = self.BitsToBytes(b)
        return B

    # algorithm 6
    def ByteDecode(self, B: bytearray, d: int):
        b = self.BytesToBits(B)
        F = []
        m = 2**d
        for i in range(0, 256):
            F[i] = 0
            for j in range(0, d):
                F[i] = F[i] + (b[i * d + j] * pow(2, j, m))
        return F

    # algorithm 7
    def SampleNTT(self, B: bytearray):
        # outputArray = a (Hat)
        outputArray = bytearray()
        XOF = SHA3.IncrementalSHAKE.IncrementalSHAKE128()
        ctx = XOF.init()
        ctx = XOF.absorb(ctx, B)
        j = 0
        while (j < 256):
            ctx, C = XOF.squeeze(ctx, 3)
            d_1 = C[0] + 256 * (C[1] % 16)
            d_2 = C[1] // 16 + 16 * C[2]
            if (d_1 < self.q):
                outputArray.append(d_1)
                j += 1
            if (d_2 < self.q and j < 256):
                outputArray.append(d_2)
                j += 1
        return outputArray
    
    # algorithm 8
    def SamplePolyCBD(self, B: bytearray, Nu: int):
        f = bytearray()

        b = self.BytesToBits(B)
        for i in range(0, 256):
            x = 0
            y = 0
            for j in range(0, Nu):
                x = x + b[2 * i * Nu + j]
                y = y + b[2 * i * Nu + Nu + j]
            f.append((x - y) % self.q)
        return f
    
    # algorithm 9
    def NTT(self, f: bytearray):
        f_hat = f.copy()
        i = 1
        l = 128
        while l >= 2:
            start = 0
            while start < 256:
                zeta = ML_KEM.ZETA_ARRAY[i]
                i = i + 1
                for j in range(start, start + l):
                    t = (zeta * f[j + l]) % self.q
                    f_hat[j + l] = (f[j] - t) % self.q
                    f[j] = (f_hat[j] + t) % self.q
                start = start + 2 * l
            l = l / 2
        return f_hat
    
    # algorithm 10
    def Inverse_NTT(self, f_hat: bytearray):
        f = f_hat.copy()
        i = 127
        l = 2
        while l <= 128:
            start = 0
            while start < 256:
                zeta = ML_KEM.ZETA_ARRAY[i]
                i = i - 1
                for j in range(0, start + l):
                    t = f[j]
                    f[j] = (t + f[j + l]) % self.q
                    f[j + l] = (zeta * (f[j + l] - t)) % self.q
                start = start + 2 * l
            l = l * 2
        
        for i in range(0, len(f)):
            f[i] = (f[i] * 3303) % self.q
        return f
    
    # algorithm 11
    def MultiplyNTTs(self, f: bytearray, g: bytearray):
        h_hat = bytearray()
        for i in range(0, 128):
            h_hat.extend(self.BaseCaseMultiply(f[2*i], f[2*i + 1], g[2*i], g[2*i + 1], ML_KEM.ZETA_PLUS1_ARRAY[i]))
        pass

    # algorithm 12
    def BaseCaseMultiply(self, a_0: int, a_1: int, b_0: int, b_1: int, gamma: int):
        c_0 = ((a_0 * b_0) + (a_1 * b_1 * gamma)) % self.q
        c_1 = ((a_0 * b_1) + (a_1 * b_0)) % self.q
        return c_0, c_1

    # algorithm 13
    def PKE_KeyGen(self, d: bytearray):
        # 1
        d_copy = d.copy()
        d_copy.append(self.k)
        ro_sigma = G(d_copy)
        rho = ro_sigma[0:32]
        sigma = ro_sigma[32:]

        #2
        N = 0
        
        #3 - 7
        A_hat = list()
        for i in range(0, self.k):
            A_hat.append(list())
            for j in range(0, self.k):
                sigma_copy = sigma.copy()
                sigma_copy.extend((i, j))
                A_hat[i].append(self.SampleNTT(sigma_copy))
        
        #8 - 11
        s = list()
        for i in range(0, self.k):
            s.append(self.SamplePolyCBD(PRF(sigma, N, self.Nu1), self.Nu1))
            N = N + 1

        #12 - 15
        e = list()
        for i in range(0, self.k):
            e.append(self.SamplePolyCBD(PRF(sigma, N, self.Nu1), self.Nu1))
            N = N + 1
        
        #16 - 17
        s_hat = list()
        e_hat = list()
        for i in range(0, self.k):
            s_hat.append(self.NTT(s[i]))
            e_hat.append(self.NTT(e[i]))
        
        #18
        t_temp = self.MultMatrixAndVector(A_hat, s_hat)
        t_hat = self.AddVectors(t_temp, e_hat)

        # 19
        ek_pke = bytearray()
        for i in range(0, self.k):
            ek_pke.extend(self.ByteEncode(t_hat[i], 12))
        ek_pke.extend(rho)

        #20
        dk_pke = bytearray()
        for i in range(0, self.k):
            dk_pke.extend(self.ByteEncode(s_hat[i], 12))
        return ek_pke,dk_pke

    # helper functions

    # 2.12
    def MultMatrixAndVector(self, A_hat: list[list[bytearray]], s_hat: list[bytearray]):
        w_hat = list()
        for i in range(0, len(A_hat)):
            w_current = bytearray(256)
            for j in range(0, self.k):
                w_temp = self.MultiplyNTTs(A_hat[i][j],s_hat[j])
                w_current = self.AddRing(w_current, w_temp)
            w_hat.append(w_current)
        return w_hat

    # 2.11
    def AddVectors(self, t_hat: list[bytearray], e_hat: list[bytearray]):
        # make the assumption that they're the same length... maybe check for length error here
        returnList = list()
        for i in range(0, len(t_hat)):
            returnList.append(self.AddRing(t_hat[i], e_hat[i]))
        return returnList

    # 2.11 (part 2)
    def AddRing(self, entry1: bytearray, entry2: bytearray):
        returnArray = bytearray()
        # make the assumption that they're the same length... maybe check for length error here
        for i in range(0, len(entry1)):
            returnArray.append((entry1[i] + entry2[i]) % self.q)
        return returnArray






def addByteArray


def PRF(s: bytearray, b: int, Nu: int):
    s_copy = s.copy()
    s_copy.append(b)
    return SHA3.SHA_3.SHAKE256().SHAKE(s_copy, 8 * 64 * Nu)

def G(c: bytearray):
    return SHA3.SHA_3.sha3_512().hash(c)


def bitrev7(i: int):
    a = (i & 0x01) << 6
    b = (i & 0x02) << 4
    c = (i & 0x04) << 2
    d = (i & 0x08) << 0
    e = (i & 0x10) >> 2
    f = (i & 0x20) >> 4
    g = (i & 0x40) >> 6
    return a + b + c + d + e + f + g



# helper function for Algorithm 4
def getBit(string: bytearray, bit_number: int):
    AndFlags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00]
    byte_number = bit_number // 8
    real_bit_number = bit_number - (8 * byte_number)
    return (string[byte_number] & AndFlags[real_bit_number]) >> (real_bit_number)

