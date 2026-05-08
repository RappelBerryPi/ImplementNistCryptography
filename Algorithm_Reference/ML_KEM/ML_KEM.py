from enum import Enum
from array import array
import copy
import sys
sys.path.append("../")
import SHA3.IncrementalSHAKE
import SHA3.SHA_3


#NOTE: BYTEARRAY will NOT WORK, THIS MUST BE A LIST OF INT because bytearray only takes numbers up to 256

class ML_KEM_PARAMETER_SET(Enum):
    ML_KEM_512 = 1
    ML_KEM_768 = 2
    ML_KEM_1024 = 3

class ML_KEM:

    _MLKEM_dictionary = {
        ML_KEM_PARAMETER_SET.ML_KEM_512: {
            "n": 256,
            "q": 3329,
            "k": 2,
            "Eta1": 3,
            "Eta2": 2,
            "d_u": 10,
            "d_v": 4,
            "requiredRBG": 128
        },
        ML_KEM_PARAMETER_SET.ML_KEM_768: {
            "n": 256,
            "q": 3329,
            "k": 3,
            "Eta1": 2,
            "Eta2": 2,
            "d_u": 10,
            "d_v": 4,
            "requiredRBG": 192
        },
        ML_KEM_PARAMETER_SET.ML_KEM_1024: {
            "n": 256,
            "q": 3329,
            "k": 4,
            "Eta1": 2,
            "Eta2": 2,
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
        self.q_div_2 = self.q // 2
        self.k = self._MLKEM_dictionary[parameterSet]["k"]
        self.Eta1 = self._MLKEM_dictionary[parameterSet]["Eta1"]
        self.Eta2 = self._MLKEM_dictionary[parameterSet]["Eta2"]
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
    def ByteEncode(self, F: array[int], d: int):
        b = list()
        for i in range (0, 256):
            a = F[i]
            # this operation essentially encodes each integer into a bit array in reverse order.
            # so the number 10 in binary would be "0b1010" 
            # this would encode it so the array ends up being b = [0, 1, 0, 1]
            # same for 128, in binary it's "0b1000 0000".
            # the array would end up encoded as b = [0, 0, 0, 0, 0, 0, 0, 1]
            # original:
            # for j in range(0, d):
            #     index = i * d + j
            #     b[index] = bool(a % 2)
            #     # a = (a - int(b[index])) // 2 # modification from actual algorithm that does a division. bitwise
            #     shift right by 1 is slightly faster and should result in exactly the same outcome
            # speedier:
            for _ in range(0, d):
                b.append(bool(a % 2))
                a = a >> 1 # modification from actual algorithm that does a division as above comment. it's subtracting and then dividing, which is the same as a bitshift with the last bit underflowing.
        B = self.BitsToBytes(b)
        return B

    # algorithm 6
    def ByteDecode(self, B: bytearray, d: int):
        b = self.BytesToBits(B)
        F = array("I") # array of unsigned ints, because 
        if (d == 12):
            m = self.q
        else:
            m = 2**d
        # original
        # for i in range(0, 256):
        #     temp = 0
        #     for j in range(0, d):
        #         temp = temp + (b[i * d + j] * pow(2, j, m))
        #     F.append(temp)
        # improved
        for i in range(0, 256):
            temp = 0
            # loop backwards
            for j in range(((i + 1) * d) - 1, i * d, -1):
                temp = (temp | b[j]) << 1
            temp = (temp | b[i * d]) % m
            F.append(temp)
        return F

    # algorithm 7
    def SampleNTT(self, B: bytearray):
        # outputArray = a (Hat)
        outputArray = array("I")
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
    def SamplePolyCBD(self, B: bytearray, Eta: int):
        f = array("I")

        b = self.BytesToBits(B)
        for i in range(0, 256):
            x = 0
            y = 0
            index = 2 * i * Eta
            for j in range(0, Eta):
                x = x + b[index + j]
                y = y + b[index + Eta + j]
            f.append((x - y) % self.q)
        return f

    
    # algorithm 9
    def NTT(self, f: array[int]):
        f_hat = copy.deepcopy(f)
        i = 1
        l = 128
        while l >= 2:
            start = 0
            while start < 256:
                zeta = ML_KEM.ZETA_ARRAY[i]
                i = i + 1
                for j in range(start, start + l):
                    t = (zeta * f_hat[j + l]) % self.q
                    f_hat[j + l] = (f_hat[j] - t) % self.q
                    f_hat[j] = (f_hat[j] + t) % self.q
                start = start + 2 * l
            l = l // 2
        return f_hat
    
    # algorithm 10
    def Inverse_NTT(self, f_hat: array[int]):
        f = copy.deepcopy(f_hat)
        i = 127
        l = 2
        while l <= 128:
            start = 0
            while start < 256:
                zeta = ML_KEM.ZETA_ARRAY[i]
                i = i - 1
                for j in range(start, start + l):
                    t = f[j]
                    f[j] = (t + f[j + l]) % self.q
                    f[j + l] = (zeta * (f[j + l] - t)) % self.q
                start = start + 2 * l
            l = l * 2
        
        for i in range(0, len(f)):
            f[i] = (f[i] * 3303) % self.q
        return f
    
    # algorithm 11
    def MultiplyNTTs(self, f: array[int], g: array[int]):
        h_hat = array("I")
        for i in range(0, 128):
            h_hat.extend(self.BaseCaseMultiply(f[2*i], f[2*i + 1], g[2*i], g[2*i + 1], ML_KEM.ZETA_PLUS1_ARRAY[i]))
        return h_hat

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
        rho_sigma = G(d_copy)
        rho = rho_sigma[0:32]
        sigma = rho_sigma[32:]

        #2
        N = 0
        
        #3 - 7
        A_hat = list()
        for i in range(0, self.k):
            A_hat.append(list())
            for j in range(0, self.k):
                rho_copy = rho.copy()
                rho_copy.extend((i, j))
                A_hat[i].append(self.SampleNTT(rho_copy))
        
        #8 - 11
        s = list()
        for i in range(0, self.k):
            s.append(self.SamplePolyCBD(PRF(sigma, N, self.Eta1), self.Eta1))
            N = N + 1

        #12 - 15
        e = list()
        for i in range(0, self.k):
            e.append(self.SamplePolyCBD(PRF(sigma, N, self.Eta1), self.Eta1))
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

        #debug
        return ek_pke,dk_pke
    
    # Algorithm 14
    def PKE_Encrypt(self, ek_pke: bytearray, m: bytearray, r: bytearray):
        #1
        N = 0

        #2
        t_hat = list()
        for i in range(0, self.k):
            t_hat.append(self.ByteDecode(ek_pke[384 * i: 384 * (i+1)], 12))

        #3
        rho = ek_pke[384 * self.k:]

        #4 - 8
        A_hat = list()
        for i in range(0, self.k):
            A_hat.append(list())
            for j in range(0, self.k):
                rho_copy = rho.copy()
                rho_copy.extend((i, j))
                A_hat[i].append(self.SampleNTT(rho_copy))

        #9 - 12
        y = list()
        for i in range(0, self.k):
            y.append(self.SamplePolyCBD(PRF(r, N, self.Eta1), self.Eta1))
            N = N + 1

        #13 - 16
        e_1 = list()
        for i in range(0, self.k):
            e_1.append(self.SamplePolyCBD(PRF(r, N, self.Eta2), self.Eta2))
            N = N + 1
        
        # 17
        e_2 = self.SamplePolyCBD(PRF(r, N, self.Eta2), self.Eta2)

        #18
        y_hat = list()
        for i in range(0, self.k):
            y_hat.append(self.NTT(y[i]))

        #19
        temp = self.MultTransposedMatrixAndVector(A_hat, y_hat)
        temp_2 = list()
        for i in range(0, self.k):
            temp_2.append(self.Inverse_NTT(temp[i]))
        u = self.AddVectors(temp_2, e_1)

        #20
        Mu = self.DecompressArray(self.ByteDecode(m, 1), 1)

        temp = self.MultVectors(t_hat, y_hat)
        temp = self.Inverse_NTT(temp)
        temp = self.AddRing(temp, e_2)
        Nu = self.AddRing(temp, Mu)

        c1 = bytearray()
        for i in range(0, self.k):
            c1.extend(self.ByteEncode(self.CompressArray(u[i], self.d_u), self.d_u))

        c2 = self.ByteEncode(self.CompressArray(Nu, self.d_v), self.d_v)

        c = c1.copy()
        c.extend(c2)
        return c

    # helper functions

    # TODO: start here and work on 5.3 next

    # 2.12
    def MultMatrixAndVector(self, A_hat: list[list[array[int]]], s_hat: list[array[int]]):
        w_hat = list()
        for i in range(0, len(A_hat)):
            w_current = array("I", [0] * 256)
            for j in range(0, self.k):
                w_temp = self.MultiplyNTTs(A_hat[i][j],s_hat[j])
                w_current = self.AddRing(w_current, w_temp)
            w_hat.append(w_current)
        return w_hat

    # 2.13
    def MultTransposedMatrixAndVector(self, A_hat: list[list[array[int]]], y_hat: list[array[int]]):
        w_hat = list()
        for i in range(0, len(A_hat)):
            w_current = array("I", [0] * 256)
            for j in range(0, self.k):
                w_temp = self.MultiplyNTTs(A_hat[j][i],y_hat[j])
                w_current = self.AddRing(w_current, w_temp)
            w_hat.append(w_current)
        return w_hat

    # 2.14
    def MultVectors(self, u_t_hat: list[array[int]], v_hat: list[array[int]]):
        z_hat = array("I", [0] * 256)
        for i in range(0, len(u_t_hat)):
            z_temp = self.MultiplyNTTs(u_t_hat[i], v_hat[i])
            z_hat = self.AddRing(z_hat, z_temp)
        return z_hat

    # 2.11
    def AddVectors(self, t_hat: list[array[int]], e_hat: list[array[int]]):
        # make the assumption that they're the same length... maybe check for length error here
        returnList = list()
        for i in range(0, len(t_hat)):
            returnList.append(self.AddRing(t_hat[i], e_hat[i]))
        return returnList

    # 2.11 (part 2)
    def AddRing(self, entry1: array[int], entry2: array[int]):
        returnArray = array("I")
        # make the assumption that they're the same length... maybe check for length error here
        for i in range(0, len(entry1)):
            returnArray.append((entry1[i] + entry2[i]) % self.q)
        return returnArray
    
    # 4.7 (floating point is NOT allowed)
    def Compress(self, x: int, d: int):
        # fips 203 says: x -> round(2^d / q * x) (mod 2^d)
        # rounding is a little harder here because we have to do some fancy math (such as barrett reduction).
        # since this isn't meant to be production code (and thus not constant time), we're going to make it simple to read.

        x = 2**d * x
        roundUp = (x % self.q > self.q_div_2)
        x = x // self.q
        if (roundUp):
            x = x + 1
        x = x % (2**d)
        return x

    # 4.8
    def Decompress(self, y: int, d: int):
        # FIPS 203 says: y -> round((q/2^d) * y)
        # because of comunicative properties of math we're going to switch this to:
        #  y -> round((q * y) / 2^d))
        # round is going to be simple here because we're dividing by a power of 2, we simply need to add and bitshift once

        y = self.q * y
        y = y >> (d-1)
        y = y + 1
        y = y >> 1
        y = y % self.q
        return y

    def CompressArray(self, x_array: array[int], d: int):
        for i in range(0, len(x_array)):
            x_array[i] = self.Compress(x_array[i], d)
        return x_array
    
    def DecompressArray(self, y_array: array[int], d: int):
        for i in range(0, len(y_array)):
            y_array[i] = self.Decompress(y_array[i], d)
        return y_array







def PRF(s: bytearray, b: int, Eta: int):
    s_copy = s.copy()
    s_copy.append(b)
    return SHA3.SHA_3.SHAKE256().SHAKE(s_copy, 8 * 64 * Eta)

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

