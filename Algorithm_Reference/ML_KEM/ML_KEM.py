from enum import Enum
from array import array
import copy
import sys
import os
sys.path.append("../")
import SHA2.SHA2
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

    def PKE_Decrypt(self, dk_pke: bytearray, c: bytearray):
        #1-2
        c1 = bytearray(c[0:(32 * self.d_u * self.k)].copy())
        c2 = bytearray(c[(32 * self.d_u * self.k):(32 * (self.d_u * self.k + self.d_v))].copy())

        #3
        u_prime = list()
        for i in range(0, self.k):
            u_prime_array_i = bytearray(c1[(32 * self.d_u * i): (32 * self.d_u * (i + 1))])
            u_prime.append(self.DecompressArray(self.ByteDecode(u_prime_array_i, self.d_u),self.d_u))
        
        #4
        Nu_prime = self.DecompressArray(self.ByteDecode(c2, self.d_v), self.d_v)

        #5
        s_hat = list()
        for i in range(0, self.k):
            section = bytearray(dk_pke[(384 * i):(384 * (i+1))])
            s_hat.append(self.ByteDecode(section, 12))

        #6
        NTT_u_prime = list()
        for i in range(0, self.k):
            NTT_u_prime.append(self.NTT(u_prime[i]))
        
        temp = self.MultVectors(s_hat, NTT_u_prime)
        temp = self.Inverse_NTT(temp)
        w = self.SubtractRing(Nu_prime, temp)

        # 7
        m = self.ByteEncode(self.CompressArray(w, 1), 1)
        return m


    ################### Main functions ########################

    # Algorithm 16
    def KeyGen_internal(self, d: bytearray, z: bytearray):
        #1
        ek_pke, dk_pke = self.PKE_KeyGen(d)

        #2
        ek = ek_pke.copy()

        #3
        dk = dk_pke.copy()
        dk.extend(ek)
        h = H(ek)
        dk.extend(H(ek))
        dk.extend(z)

        return ek,dk

    #Algorithm 17
    def Encaps_internal(self, ek: bytearray, m: bytearray):
        temp = m.copy()
        temp.extend(H(ek))
        K_r = G(temp)
        K = K_r[0:32]
        r = K_r[32:]
        c = self.PKE_Encrypt(ek, m, r)
        return K, c

    #Algorithm 18
    def Decaps_internal(self, dk: bytearray, c: bytearray):
        # 1 - 4
        dk_pke = bytearray(dk[0:(384*self.k)])
        ek_pke = bytearray(dk[(384*self.k):(768*self.k + 32)])
        h = bytearray(dk[(768*self.k + 32):(768*self.k + 64)])
        z = bytearray(dk[(768*self.k + 64):(768*self.k + 96)])
        #5
        m_prime = self.PKE_Decrypt(dk_pke, c)

        #6
        temp = m_prime.copy()
        temp.extend(h)
        K_r_prime = G(temp)
        K_prime = K_r_prime[0:32]
        r_prime = K_r_prime[32:]

        #7
        temp = z.copy()
        temp.extend(c)
        K_bar = J(temp)

        #8
        c_prime = self.PKE_Encrypt(ek_pke, m_prime, r_prime)
        #debug
        if (c != c_prime):
            K_prime = K_bar.copy()
        return K_prime

    # Algorithm 19
    def KeyGen(self):
        d = bytearray(os.urandom(32))
        z = bytearray(os.urandom(32))
        if (d == None or z == None):
            raise ValueError("Unable to generate a random value, KeyGen Failed")
        ek, dk = self.KeyGen_internal(d, z)
        return ek, dk

    #Algorithm  20
    def Encaps(self, ek: bytearray):
        # check as per 7.2
        if (len(ek) != ((384 * self.k) + 32)):
            raise ValueError("Invalid Encapsulation Key")
            
        temp = list()
        for i in range(0, self.k):
            temp.append(self.ByteDecode(ek[384 * i: 384 * (i+1)], 12))

        test = bytearray()
        for i in range(0, self.k):
            test.extend(self.ByteEncode(temp[i], 12))

        if (test != ek[0:(384*self.k)]):
            raise ValueError("Invalid Encapsulation Key")

        #1
        m = bytearray(os.urandom(32))
        if (m == None):
            raise ValueError("Unable to generate a random value, Encaps failed")
        K, c = self.Encaps_internal(ek, m)
        return K, c
    
    #Algorithm 21
    def Decaps(self, dk: bytearray, c: bytearray):
        # Check as per 7.3

        if (len(c) != (32 * (self.d_u * self.k + self.d_v))):
            raise ValueError("Invalid CipherText")
        
        if (len(dk) != (768 * self.k + 96)):
            raise ValueError("Invalid Decapsulation Key")

        test = H(bytearray(dk[(384 * self.k):(768 * self.k + 32)]))
        if (test != dk[(768 * self.k + 32):(768 * self.k + 64)]):
            raise ValueError("Invalid Decapsulation Key")

        #1
        K_prime = self.Decaps_internal(dk, c)

        #2
        return K_prime


    # helper functions

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

    # ?????????????
    def SubtractRing(self, entry1: array[int], entry2: array[int]):
        returnArray = array("I")
        # make the assumption that they're the same length... maybe check for length error here
        for i in range(0, len(entry1)):
            returnArray.append((entry1[i] - entry2[i]) % self.q)
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

def H(c: bytearray):
    #return SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_512).hash(c)
    return SHA3.SHA_3.sha3_256().hash(c)

def J(c: bytearray):
    return SHA3.SHA_3.SHAKE256().SHAKE(c, 8 * 32)

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

if __name__ == "__main__":
    # import os
    # X = ML_KEM(ML_KEM_PARAMETER_SET.ML_KEM_512)
    # d = bytearray(os.urandom(32))   
    # ek_pke, dk_pke = X.PKE_KeyGen(d)
    # m = bytearray(os.urandom(32))
    # r = bytearray(os.urandom(32))
    # c = X.PKE_Encrypt(ek_pke, m, r)
    # m_prime = X.PKE_Decrypt(dk_pke, c)
    # print(m == m_prime)

    # X = ML_KEM(ML_KEM_PARAMETER_SET.ML_KEM_512)
    # d = bytearray(os.urandom(32))   
    # z = bytearray(os.urandom(32))   
    # ek, dk = X.KeyGen_internal(d, z)
    # m = bytearray(os.urandom(32))
    # K, c = X.Encaps_internal(ek, m)
    # m_prime = X.Decaps_internal(dk, c)
    # print(K)
    # print(m_prime)

    X = ML_KEM(ML_KEM_PARAMETER_SET.ML_KEM_512)
    ek, dk = X.KeyGen()
    K, c = X.Encaps(ek)
    K_prime = X.Decaps(dk, c)
    print(K)
    print(K_prime)

    # Taken from
    # https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
    ek = bytearray.fromhex( "9405C22FB76F6C154B35E49DA6119D72DC139BB52A057B6E4F4A177FE88568B06D94C0A59562BC2BEA86EA7CB1F078223E7743ED8B6DCFA2CBE64699C773A5ED0C0935917B9E3015DB102C8B98A05559211B563EA1B0B7012C6332262FFFC09E779A1068380E9FE1B0E0948D00B8883F96A3D555A52D18687491916065A9E56A075464B625507560829CB94A2FC57C7CBC96864C0201F1D34BB21B0133A50C213077C7DC4CA0F871D1FB4AA8C99D7CD245607954A3E45DFBB24C320B97DD1231CA5A44EC041BE9D15504A72DB425CADAF57AD0E72CCBAB789FACAB053377F56B891FF7932F3A2A0B618544CBCB99158246F183E313443CC35BCEC71E9D30954C404D84540BE4152B3794A582953207813685A05F52624BD7926CD3812D53CAAAB2C392FFB26BB3A06F7A1AC1D0F145C9434B86695B58A673B4955ADA329D5B572152727CA3963F54898D39F38DF578965436025BD8C1C6342629BBA98B300FBE8AAC379BCE1212A247BB452701A82810B825066BE058CB78DB9E83A3ACC6637955411A7FA3C2AB7692A279A210CB9040CA1B36B65041B1A8AF874701DC3036035A96D22B38F4CBEDF72777C61C3248328B51A191690A9508B6A1185F0B890A91F0CF43E4127C51509E8B5AE6588863F72595A7524708A2A6A385A385BF750BBCD3B7326BA99F37F6402E1978AE963AE207CF1FAC8028024AF63CB6CA32298626CC8D935B72D8556024824260BA2E427C3930002023B7EFD41693E44D4482AF9A4463023869DE85820C848520D2B465905433848A3589ABFD4C39DB311B93B34086D12C4C8243518A75C14A69DA9235A6FA305258BF7BB5ADA8A428F6063FA1D437C4B36394727FC06957B8D6BB21F409969290E1346698A25E61937AE1E23BDFE09A53B437F172A57BB61FCC569746054601415E6E315648E03DA71239BF869E1F669B8838A486FB2E4F489DC8E2747DF4849B83B165E95D23E4CCCCB5C414934549B9046F359E06B6ABFEFA0E4745A346451EF8791D5582AB2DB22EBDD1126568930264C19F1BA747296B40E284A45459398587975C88071CBBF6C9275DC8C81C661A020443C39208359AF0A721A303479A6DA0357402827F09653C7A2CCDDD")
    dk = bytearray.fromhex( "BE26809AA451F5925CE5B1311789AFE966C34EA9B677EC50624109CE3A85FE560478E09B99D16C57D612CD8BAF90486B48170ADDB370A0C613CBE3BC04785F8B2B688215BFEEC192EB39CD0239751484161685A8197987BD600D72A0BE008C4BA9C56B9C495952435F29716C3C69660BDBBB4F66652A3A7EA08C6B8175C0D7C563C4060EADB1987322A2467C7E672BB54B2187E37952B6BC6C001B5DAA969E86F2120284213156A80F0BA258545549778D6D65AFBAA9CB073549AFF577CAB079C625236AE5C003158D0ACA16A91A9F45C32FDC182B800798DC2540A7011294D81EA3644467238C78C84D892A61133016E4768042A14A2C13598B51600B219C0C1B4E88C979DDBCBA52B836FA4095C2E47943A27010A58BB4065929EA6E33648CF9D2A121871838B39FFB3291E5781A06B1266542CE2A85A8BEBA7287703085C4B808E7C15448272FB37E9A04297CCC26EAC658CC30A4FD4C72F00070F04AC4BA30486D8396C149A4053C39A2C00A33CBC41FB563E7B38AE1913032311617D45BC83C59DC6845CE991D65BC442A39AF5C7A5638EA9BA93678E28A73EC24C032B4796F44385E2492E02734A5EA3972B5CA726A431C3C41ABFC1B637311F781629E69C0291A5AFF8AA8258129186CAF17AA4BBC927F76045076853437B95B0FD531C488C336D43504F95C82B970DD19202973C8CB12C468A9A17D644EAAD75ECEE7440B9901DE7998BDDC737014C1461137EFA28D32DCCF4AFC9B5089B6067A3D727510085950446AAA2A272CBC06B3D0E236DB180377810C435AAC5A60553BD0AE140969D8D2CDEB78B3D097540C6A9EE2613296A5AA4D6BCAFAFC4580896529E15308BC05BDD36A5DD9B6EF989080C2431ADCB35D8357097CAC6EB7BDAD905FD668A3ECF690DA814456933E6089641F252DAA90799E39AB6F037F79C5B13750005E202B98BB50C4D94B512533F4C2A67B3C31B2E03E691AA41867B8D0C93A73A27CA49A2DDCDC0188FC1965B579E516AAB43527D1D69DC723BCA288C5FB73C99A399A7D4107C0E76E00C7C9DC52095BB925E24A2575420BB3F4CDEB798CF377469405C22FB76F6C154B35E49DA6119D72DC139BB52A057B6E4F4A177FE88568B06D94C0A59562BC2BEA86EA7CB1F078223E7743ED8B6DCFA2CBE64699C773A5ED0C0935917B9E3015DB102C8B98A05559211B563EA1B0B7012C6332262FFFC09E779A1068380E9FE1B0E0948D00B8883F96A3D555A52D18687491916065A9E56A075464B625507560829CB94A2FC57C7CBC96864C0201F1D34BB21B0133A50C213077C7DC4CA0F871D1FB4AA8C99D7CD245607954A3E45DFBB24C320B97DD1231CA5A44EC041BE9D15504A72DB425CADAF57AD0E72CCBAB789FACAB053377F56B891FF7932F3A2A0B618544CBCB99158246F183E313443CC35BCEC71E9D30954C404D84540BE4152B3794A582953207813685A05F52624BD7926CD3812D53CAAAB2C392FFB26BB3A06F7A1AC1D0F145C9434B86695B58A673B4955ADA329D5B572152727CA3963F54898D39F38DF578965436025BD8C1C6342629BBA98B300FBE8AAC379BCE1212A247BB452701A82810B825066BE058CB78DB9E83A3ACC6637955411A7FA3C2AB7692A279A210CB9040CA1B36B65041B1A8AF874701DC3036035A96D22B38F4CBEDF72777C61C3248328B51A191690A9508B6A1185F0B890A91F0CF43E4127C51509E8B5AE6588863F72595A7524708A2A6A385A385BF750BBCD3B7326BA99F37F6402E1978AE963AE207CF1FAC8028024AF63CB6CA32298626CC8D935B72D8556024824260BA2E427C3930002023B7EFD41693E44D4482AF9A4463023869DE85820C848520D2B465905433848A3589ABFD4C39DB311B93B34086D12C4C8243518A75C14A69DA9235A6FA305258BF7BB5ADA8A428F6063FA1D437C4B36394727FC06957B8D6BB21F409969290E1346698A25E61937AE1E23BDFE09A53B437F172A57BB61FCC569746054601415E6E315648E03DA71239BF869E1F669B8838A486FB2E4F489DC8E2747DF4849B83B165E95D23E4CCCCB5C414934549B9046F359E06B6ABFEFA0E4745A346451EF8791D5582AB2DB22EBDD1126568930264C19F1BA747296B40E284A45459398587975C88071CBBF6C9275DC8C81C661A020443C39208359AF0A721A303479A6DA0357402827F09653C7A2CCDDD78688324A1678F678D49AE2658E0DDD0DA7FD25FF8375BD9708415D6BD80AA8C23425D1B45CFECFDADFEFBA627B7F88C03E56DF0227510BC47AE6EBA8B92C1A8")
    c = bytearray.fromhex( "FCDD461B68BB4A153F9203BD9822D4C4F6305ADA8786C564DA4F31518F8D4AB51D9485673921777D439482DA99D70482D0C3EAC998541CEC67759A19865D3EB42F3B7BA83180F6E9968EA84747A8B0E7C5CC3159A7BE5D471BAC5313C055BBB731CC73565E90FC5A64DA299C38C632C054A1E3EC1F13D0D332F8437F273F149CA419A922BCCB0AAF454162282A0080C6C31530C9A620A682069309B039264FB7A82057047ADEFE3C598C8FD17BFBB48CBDF7DF4326C69519615A6D81A797107532FE503ED0F8C7FEAE197E329C05D4041DCB6B3DA4428112FF2702994682BFF8FB7E6268162D3C85BB40574D8FC256335DA513E5C1BC06271DD2219674864BB1F51BD2CEED41ED425BF27A27B9CE312EA9AC0753D102D15DE9B3A668C2E154817A8AE7B6F2F5D0A38A0E6A46E06E1309CC9FF1879F6A5C8D7F3D56EBCA1BCCEF42ED57EDD349F321C07DA2F5D9242E6F31B9A0EA25BB904E19E7B771068EFAE868CCC4EBD72CBA16865698AA64DCC33D7BFAC4D8C472D31A7AA65733B54CB41E79CF16BBFC930EDD78CA21817DD5A61066CFF379363B5E43DE320066736879D5C4F16F4431D71AD9EF7E18D3166AF1D0A2C7126BBB542F182F20FD1A4AC88A218A46A849797A6C459029AF2E61C9707C7F142F333D3ED061872449D00F9744693BE1118F0597A61F1A808976504A3FE1F9A4582547AD780EA05A318FDDEC654F0826D1344BD986238A214840257B6E857C9A032579179FC374174E640AB5540865DE606948FB3A02EA70742BA7A08617B6FB01239F4D5138BB7A28836368E1E6CA63BFD9C3924261289BF6C1F9C3C040595CD52E4643F6C2726F3102E308494F4B33E312D59345279333A2AF49C157B4FE55D42083CBF436C66E0031609ED4BDED3DD7A54C98938BFB41A4F4DAF3A96B20E29F54BB7CC6742AB563467DA923D682E91ABA279A616E52DAAC56D07919697A5CB173FA24F09BC778AB1103F6F03719D088C549B18ED72ADF6738BC82BF4370AE9A7BBBCFB1C78717E11354DCF42654675AA0A45108F5B67D2CC77DC200A0F97BAF667A242627298E57BE6C761EC4")
    # "k": "9B0E2A90368B07C5A94CD4E880EEE7814E1703D09369DCB9D3C2AA079FD9F75A",

    print(X.Decaps(dk, c).hex())
# "k": "4B7B1514D1BC9808F80E3BEE7B528E13B753C99D153F7EA116A5887063BFCACF",
# "m": "19C44D35AB9EF31B1360F0BF33CF63D80E405962D698415C5888F0AF385DCFF4"