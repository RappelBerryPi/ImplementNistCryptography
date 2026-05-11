from enum import Enum
import os
sys.path.append("../")
import SHA2.SHA2
import SHA3.IncrementalSHAKE
import SHA3.SHA_3
from array import array
from copy import deepcopy


#NOTE: BYTEARRAY will NOT WORK, THIS MUST BE A LIST OF INT because bytearray only takes numbers up to 256

class ML_DSA_PARAMETER_SET(Enum):
    ML_DSA_44 = 1
    ML_DSA_65 = 2
    ML_DSA_87 = 3

class KnownPreHash(Enum):
    SHA2_256 = 1
    SHA2_384 = 2
    SHA2_512 = 3
    SHA2_512_256 = 4
    SHA3_256 = 5
    SHA3_384 = 6
    SHA3_512 = 7 
    SHAKE128 = 8 
    SHAKE256 = 9 

class ML_DSA:

    _MLDSA_dictionary = {
        ML_DSA_PARAMETER_SET.ML_DSA_44: {
            "q": 8380417,
            "zeta": 1753,
            "d": 13,
            "tau": 39,
            "lambda": 128,
            "gamma_1": 2**17,
            "gamma_2": (8380417-1) // 88,
            "k": 4,
            "l": 4,
            "eta": 2,
            "beta": 78,
            "omega": 80
        },
        ML_DSA_PARAMETER_SET.ML_DSA_65: {
            "q": 8380417,
            "zeta": 1753,
            "d": 13,
            "tau": 49,
            "lambda": 192,
            "gamma_1": 2**19,
            "gamma_2": (8380417-1) // 32,
            "k": 6,
            "l": 5,
            "eta": 4,
            "beta": 196,
            "omega": 55
        },
        ML_DSA_PARAMETER_SET.ML_DSA_87: {
            "q": 8380417,
            "zeta": 1753,
            "d": 13,
            "tau": 60,
            "lambda": 256,
            "gamma_1": 2**19,
            "gamma_2": (8380417-1) // 32,
            "k": 8,
            "l": 7,
            "eta": 2,
            "beta": 120,
            "omega": 75
        }
    }

    ZETAS = [ 0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983 ]

    def __init__(self, parameterSet: ML_DSA_PARAMETER_SET):
        self.q = self._MLDSA_dictionary[parameterSet]["q"]
        self.zeta = self._MLDSA_dictionary[parameterSet]["zeta"]
        self.d = self._MLDSA_dictionary[parameterSet]["d"]
        self.tau = self._MLDSA_dictionary[parameterSet]["tau"]
        self.Lambda = self._MLDSA_dictionary[parameterSet]["lambda"]
        self.gamma_1 = self._MLDSA_dictionary[parameterSet]["gamma_1"]
        self.gamma_2 = self._MLDSA_dictionary[parameterSet]["gamma_2"]
        self.k = self._MLDSA_dictionary[parameterSet]["k"]
        self.l = self._MLDSA_dictionary[parameterSet]["l"]
        self.eta = self._MLDSA_dictionary[parameterSet]["eta"]
        self.beta = self._MLDSA_dictionary[parameterSet]["beta"]
        self.omega = self._MLDSA_dictionary[parameterSet]["omega"]
        self.dimensions = (self.k, self.l)
        self.d_2 = 2**(self.d - 1)

    # Algorithm 1
    def KeyGen(self):
        Xi = bytearray(os.urandom(32))
        if (Xi == None):
            raise ValueError("Unable to generate a random number")
        return self.KeyGen_internal(Xi)

    # Algorithm 2
    def Sign(self, sk: bytearray, M: bytearray, ctx: bytearray):
        #1 - 3
        if (len(ctx) > 255):
            raise ValueError("context string too long")

        #5 - 8
        rnd = bytearray(os.urandom(32))
        if (rnd == None):
            raise ValueError("Unable to generate a random number")

        #10
        temp = bytearray()
        temp.extend(IntegerToBytes(0,1))
        temp.extend(IntegerToBytes(len(ctx),1))
        temp.extend(ctx)

        M_prime = BytesToBits(temp)

        # TODO: ensure to encode M as bits
        M_prime.extend(M)

        #11

        sigma = self.Sign_internal(sk, M_prime, rnd)
        return sigma

    # Algorithm 3
    def Verify(self, pk: bytearray, M: bytearray, sigma: bytearray, ctx: bytearray):
        # 1 - 3
        if (len(ctx) > 255):
            raise ValueError("context string too long")

        #5 
        temp = bytearray()
        temp.extend(IntegerToBytes(0,1))
        temp.extend(IntegerToBytes(len(ctx),1))
        temp.extend(ctx)

        M_prime = BytesToBits(temp)

        # TODO: ensure to encode M as bits
        M_prime.extend(M)

        return self.Verify_internal(pk, M_prime, sigma)

    # Algorithm 4
    def PreHashSign(self, sk: bytearray, M: bytearray, ctx: bytearray, PH: KnownPreHash):
        #1 - 3
        if (len(ctx) > 255):
            raise ValueError("context string too long")

        #5 - 8
        rnd = bytearray(os.urandom(32))
        if (rnd == None):
            raise ValueError("Unable to generate a random number")
        
        #10 - 22
        OID = bytes()
        PH_m = bytearray()
        match PH:
            case KnownPreHash.SHA2_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_256).hash(M)
            case KnownPreHash.SHA2_384:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_384).hash(M)
            case KnownPreHash.SHA2_512:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_512).hash(M)
            case KnownPreHash.SHA2_512_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_512_256).hash(M)
            case KnownPreHash.SHA3_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08])
                PH_m = SHA3.SHA_3.sha3_256().hash(M)
            case KnownPreHash.SHA3_384:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09])
                PH_m = SHA3.SHA_3.sha3_384().hash(M)
            case KnownPreHash.SHA3_512:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a])
                PH_m = SHA3.SHA_3.sha3_512().hash(M)
            case KnownPreHash.SHAKE128:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b])
                PH_m = SHA3.SHA_3.SHAKE128().SHAKE(M, 256)
            case KnownPreHash.SHAKE256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c])
                PH_m = SHA3.SHA_3.SHAKE256().SHAKE(M, 512)
            case _:
                raise ValueError("Unknown Hash type")


        temp = bytearray()
        temp.extend(IntegerToBytes(1,1))
        temp.extend(IntegerToBytes(len(ctx),1))
        temp.extend(ctx)
        temp.extend(OID)
        temp.extend(PH_m)

        M_prime = BytesToBits(temp)

        sigma = self.Sign_internal(sk, M_prime, rnd)
        return sigma

    # Algorithm 5
    def PreHashVerify(self, pk: bytearray, M: bytearray, sigma: bytearray, ctx: bytearray, PH: KnownPreHash):
        #1 - 3
        if (len(ctx) > 255):
            raise ValueError("context string too long")

        #5 - 17
        OID = bytes()
        PH_m = bytearray()
        match PH:
            case KnownPreHash.SHA2_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_256).hash(M)
            case KnownPreHash.SHA2_384:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_384).hash(M)
            case KnownPreHash.SHA2_512:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_512).hash(M)
            case KnownPreHash.SHA2_512_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06])
                PH_m = SHA2.SHA2.SHA2_Instance(SHA2.SHA2.SHA2.SHA2_512_256).hash(M)
            case KnownPreHash.SHA3_256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08])
                PH_m = SHA3.SHA_3.sha3_256().hash(M)
            case KnownPreHash.SHA3_384:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09])
                PH_m = SHA3.SHA_3.sha3_384().hash(M)
            case KnownPreHash.SHA3_512:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a])
                PH_m = SHA3.SHA_3.sha3_512().hash(M)
            case KnownPreHash.SHAKE128:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b])
                PH_m = SHA3.SHA_3.SHAKE128().SHAKE(M, 256)
            case KnownPreHash.SHAKE256:
                OID = bytearray([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c])
                PH_m = SHA3.SHA_3.SHAKE256().SHAKE(M, 512)
            case _:
                raise ValueError("Unknown Hash type")


        temp = bytearray()
        temp.extend(IntegerToBytes(1,1))
        temp.extend(IntegerToBytes(len(ctx),1))
        temp.extend(ctx)
        temp.extend(OID)
        temp.extend(PH_m)

        M_prime = BytesToBits(temp)

        return self.Verify_internal(pk, M_prime, sigma)

    # Algorithm 6
    def KeyGen_internal(self, Xi: bytearray):
        #1 
        temp = Xi.copy()
        temp.extend(IntegerToBytes(self.k, 1))
        temp.extend(IntegerToBytes(self.l, 1))
        Seeds = H(temp, 128)
        rho = Seeds[0:32].copy()
        rho_prime = Seeds[32:96].copy()
        K = Seeds[96:].copy()

        #3
        A_hat = self.ExpandA(rho)

        #4
        s_1, s_2 = self.ExpandS(rho_prime)

        #5
        temp = list()
        for i in range(0, self.l):
            temp.append(self.NTT(s_1[i]))
        temp = self.NTT(s_1)
        temp = self.MatrixVectorNTT(A_hat, temp)
        temp = self.Inverse_NTT(temp)
        t = self.AddVectorNTT(temp, s_2)

        #6 

        t_1, t_0 = self.Power2RoundVector(t)

        #8
        pk = self.pkEncode(rho, t_1)

        #9
        tr = H(pk, 64)

        #10
        sk = self.skEncode(rho, K, tr, s_1, s_2, t_0)
        return pk, sk

        #TODO: create NTT, Inverse_NTT, AddVectorNTT, Power2Round and others

    # Helper functions

    # Algorithm 9
    def IntegerToBits(self, x: int, alpha: int):
        bitArray = []
        for _ in range(0, alpha):
            bitArray.append(x & 0x01)
            x = x >> 1
        return bitArray
    
    #algorithm 12
    # copied from Keccak
    def BitsToBytes(self, y: list):
        string = bytearray()
        for i in range(0, len(y), 8):
            byte = y[i + 0] << 0
            byte = byte | (y[i + 1] << 1)
            byte = byte | (y[i + 2] << 2)
            byte = byte | (y[i + 3] << 3)
            byte = byte | (y[i + 4] << 4)
            byte = byte | (y[i + 5] << 5)
            byte = byte | (y[i + 6] << 6)
            byte = byte | (y[i + 7] << 7)
            string.append(byte)
        if (len(y) % 8 != 0):
            raise ValueError("Unable to handle byte aligned bits")
        return string


    # Algorithm 16
    def SimpleBitPack(self, w: array[int], b: int):
        z = list()
        b_bit_len = b.bit_length()
        for i in range(0, 256):
            z.extend(self.IntegerToBits(w[i], b_bit_len))
        return self.BitsToBytes(z)
    
    def BitPack(self, w: array[int], a: int, b: int):
        z = list()
        a_b_bit_len = (a + b).bit_length()
        for i in range(0, 256):
            z.extend(self.IntegerToBits(b - w[i], a_b_bit_len))
        return self.BitsToBytes(z)

    # Algorithm 22
    def pkEncode(self, rho: bytearray, t_1: list[array[int]]):
        pk = rho.copy()
        for i in range(0, self.k):
            pk.extend(self.SimpleBitPack(t_1[i], 2**(((self.q - 1) - self.d).bit_length) - 1))
        return pk
    
    # algorithm 23
    def skEncode(self, rho: bytearray, K: bytearray, tr: bytearray, s_1: list[array[int]], s_2: list[array[int]], t_0: list[array[int]]):
        sk = rho.copy()
        sk.extend(K)
        sk.extend(tr)
        for i in range(0, self.l):
            sk.extend(self.BitPack(s_1[i], self.eta, self.eta))
        for i in range(0, self.k):
            sk.extend(self.BitPack(s_2[i], self.eta, self.eta))
        for i in range(0, self.k):
            sk.extend(self.BitPack(t_0[i], 2**(self.d-1) - 1, 2**(self.d - 1)))
        return sk

    # Algorithm 32
    def ExpandA(self, rho: bytearray):
        A_hat = list()
        for r in range(0, self.k):
            A_hat.append(list())
            for s in range(0, self.l):
                rho_prime = rho.copy()
                rho_prime.append(IntegerToBytes(s,1))
                rho_prime.append(IntegerToBytes(r,1))
                A_hat[r].append(self.RejNTTPoly(rho_prime))
        return A_hat
    
    # Algorithm 33
    def ExpandS(self, rho: bytearray):
        s_1 = list()
        for r in range(0, self.l):
            temp = rho.copy()
            temp.extend(IntegerToBytes(r, 2))
            s_1.append(self.RejBoundedPoly(temp))
        s_2 = list()
        for r in range(0, self.k):
            temp = rho.copy()
            temp.extend(IntegerToBytes(r + self.l, 2))
            s_2.append(self.RejBoundedPoly(temp))
        return s_1, s_2

    # Algorithm 30
    def RejNTTPoly(self, rho: bytearray):
        a_hat = array("I", [0] * 256)
        j = 0
        G = SHA3.IncrementalSHAKE.IncrementalSHAKE128()
        ctx = G.init()
        ctx = G.absorb(ctx, rho)
        while j < 256:
            ctx, s = G.squeeze(ctx, 3)
            a_hat[j] = self.CoeffFromThreeBytes(s[0], s[1], s[3])
            if (a_hat[j] != None):
                j = j + 1
        return a_hat
    
    # Algorithm 31
    def RejBoundedPoly(self, rho: bytearray):
        a = array("I")
        j = 0
        H = SHA3.IncrementalSHAKE.IncrementalSHAKE256()
        ctx = H.init()
        ctx = H.absorb(ctx, rho)
        while j < 256:
            z = H.squeeze(ctx,1)
            z_0 = self.CoeffFromHalfByte(z % 16)
            z_1 = self.CoeffFromHalfByte(z // 16)
            if (z_0 != None):
                a.append(z_0)
                j = j + 1
            if (z_1 != None and j < 256):
                a.append(z_1)
                j = j + 1
        return a
    
    # algorithm 35
    # power2 Round takes advantage of this special modulus (mod+- 2**d)
    # this means that the modulus is taken (as normal), but then shifted to be between the range of
    # -ceiling(m / 2) < X <= floor(m // 2)
    # let's use 9 as our "M"
    # celing m // 2 = 5
    # floor (m // 2) = 4
    # range is -5 < X <= 4
    # so the real range is -4, -4
    # which checks out: -4, -3, -2, -1, 0, 1, 2, 3, 4
    #                    1   2   3   4  5  6  7  8  9
    # or (normal mod)    0   1   2   3  4  5  6  7  8
    # so this would be the same as y = (x % mod) - (mod // 2)
    # if we test a random value (153), this would normally give us 0
    # because of the shift, this now gives us -4
    # I'm going to go ahead and pre-calculate this value because powerround2 is called thousands of times.
    # the mod // 2 is going to be put in self.d_2, and it's just going to be 2**(self.d - 1) (because that's equivelent)
    # this happens to be the number 4096, but I'm not hardcoding that
    def Power2Round(self, r: int):
        dPow2 = 2**self.d
        r_1 = r % self.q
        r_0 = (r_1 % dPow2) - self.d_2
        r_1 = (r_1 - r_0) >> self.d
        return r_1, r_0
    
    # algorithm 35 ancillary
    def Power2RoundPoly(self, r: array[int]):
        r_prime_1 = array("i")
        r_prime_0 = array("i")
        for i in range(0, 256):
            r_1, r_0 = self.Power2Round(r[i])
            r_prime_1.append(r_1)
            r_prime_0.append(r_0)
        return r_prime_1, r_prime_0
    
    # algorithm 35 ancillary 2
    def Power2RoundVector(self, r: list[array[int]]):
        r_1 = list()
        r_0 = list()
        for i in range(0, len(r)):
            r_1_temp, r_0_temp = self.Power2RoundPoly(r[i])
            r_1.append(r_1_temp)
            r_0.append(r_0_temp)
        return r_1, r_0




    # Algorithm 14
    # the input here really is three bytes, but in python these get represented as ints
    # the below is their definition in the paper, I'm going to speed up a bit with bit operations
    # def CoeffFromThreeBytes(self, b_0: int, b_1: int, b_2: int):
    #     b_2_prime = b_2
    #     if b_2_prime > 127:
    #         b_2_prime = b_2_prime - 128
    #     z = 2**16 * b_2_prime + 2**8 * b_1 + b_0
    #     if (z < self.q):
    #         return z
    #     return None
    def CoeffFromThreeBytes(self, b_0: int, b_1: int, b_2: int):
        b_2 = b_2 & 0b0111_1111
        z = (b_2 << 16) + (b_1 << 8) + b_0
        if (z < self.q):
            return z
        return None
    
    # Algorithm 15
    # below is a copy of what they have. the input b is always 0 - 16
    def CoeffFromHalfByte(self, b: int):
        if (self.eta == 2 and b < 15):
            return 2 - (b % 5)
        else:
            if (self.eta == 4 and b < 9):
                return 4 - b
            else:
                return None
    
    # algorithm 41
    def NTT(self, w: array[int]):
        w_hat = deepcopy(w)
        m = 0
        length = 128
        while length >= 1:
            start = 0
            while start < 256:
                m = m + 1
                z = ML_DSA.ZETAS[m]
                for j in range(start, start + length):
                    t = (z * w_hat[j + length]) % self.q
                    w_hat[j + length] = (w_hat[j] - t) % self.q
                    w_hat[j] = (w_hat[j] + t) % self.q
                start = start + 2 * length
            length = length >> 1
        return w_hat
    
    # algorithm 42
    def Inverse_NTT(self, w_hat: array[int]):
        w = deepcopy(w_hat)
        m = 256
        length = 1
        while length < 256:
            start = 0
            while start < 256:
                m = m - 1
                z = (-(self.ZETAS[m])) % self.q
                for j in range(start, start + length):
                    t = w[j]
                    w[j] = (t + w[j + length]) % self.q
                    w[j + length] = (t - w[j + length]) % self.q
                    w[j + length] = (z * w[j + length]) % self.q
                start = start + 2 * length
            length = 2 * length
        f = 8347681 # 256^-1 % self.q (multiplicative modular inverse) can be calculated in python using fermat's little theorem or the extended euclidean algorithm.
        # example of above comment calculation
        # f = pow(256, self.q - 2, self.q)
        for j in range(0, 256):
            w[j] = (f * w[j]) % self.q
        return w
    
    # algorithm 43
    # skip

    #algorithm 44
    def AddNTT(self, a_hat: array[int], b_hat: array[int]):
        c_hat = deepcopy(a_hat)
        for i in range(0, 256):
            c_hat = c_hat[i] + b_hat[i]
        return c_hat

    #algorithm 45
    def MultiplyNTT(self, a_hat: array[int], b_hat: array[int]):
        c_hat = deepcopy(a_hat)
        for i in range(0, 256):
            c_hat = c_hat[i] * b_hat[i]
        return c_hat

    #algorithm 46
    def AddVectorNTT(self, v_hat: list[array[int]], w_hat: list[array[int]]):
        u_hat = list()
        for i in range(0, self.l):
            u_hat.append(self.AddNTT(v_hat[i], w_hat[i]))
        return u_hat
    
    #algorithm 47
    def ScalarVectorNTT(self, c_hat: array[int], v_hat: list[array[int]]):
        w_hat = list()
        for i in range(0, self.l):
            w_hat.append(self.MultiplyNTT(c_hat, v_hat[i]))
        return w_hat
    
    #algorithm 48
    def MatrixVectorNTT(self, M_hat: list[list[array[int]]], v_hat: list[array[int]]):
        w_hat = list()
        for i in range(0, self.k):
            w_current = array("I", [0] * 256)
            for j in range(0, self.l):
                w_temp = self.MultiplyNTT(M_hat[i][j], v_hat[j])
                w_current = self.AddNTT(w_current, w_temp)
            w_hat.append(w_current)
        return w_hat


#Algorithm 11
def IntegerToBytes(x: int, a: int):
    return x.to_bytes(a, "little")

def H(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE256().SHAKE(str, 8 * l)

def G(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE128().SHAKE(str, 8 * l)

#H.Init , absorb, squeeze -> shake256

#G.Init , absorb, squeeze -> shake128
