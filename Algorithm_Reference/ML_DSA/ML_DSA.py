from enum import Enum
import sys
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

        M_prime = self.BytesToBits(temp)

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

        M_prime = self.BytesToBits(temp)

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

        M_prime = self.BytesToBits(temp)

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

        M_prime = self.BytesToBits(temp)

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
        temp = self.MatrixVectorNTT(A_hat, temp)

        temp2 = list()
        for i in range(0, len(temp)):
            temp2.append(self.Inverse_NTT(temp[i]))
        t = self.AddVectorNTT(temp2, s_2)

        #6 

        t_1, t_0 = self.Power2RoundVector(t)

        #8
        pk = self.pkEncode(rho, t_1)

        #9
        tr = H(pk, 64)

        #10
        sk = self.skEncode(rho, K, tr, s_1, s_2, t_0)
        return pk, sk

    # Algorithm 7

    def Sign_internal(self, sk: bytearray, M_prime: list, rnd: bytearray):
        #1
        rho, K, tr, s_1, s_2, t_0 = self.skDecode(sk)

        #2
        s_hat_1 = list()
        for i in range(0, len(s_1)):
            s_hat_1.append(self.NTT(s_1[i]))
        
        #3
        s_hat_2 = list()
        for i in range(0, len(s_2)):
            s_hat_2.append(self.NTT(s_2[i]))

        #4
        t_hat_0 = list()
        for i in range(0, len(t_0)):
            t_hat_0.append(self.NTT(t_0[i]))

        #5
        A_hat = self.ExpandA(rho)

        #6
        # This is going to throw an error
        temp = self.BytesToBits(tr)
        temp.extend(M_prime)
        temp = self.BitsToBytes(temp)
        Mu = H(temp, 64)

        #7
        temp = K.copy()
        temp.extend(rnd)
        temp.extend(Mu)
        rho_double_prime = H(temp, 64)

        #8 - 9
        k = 0
        z = None
        h = None
        #10 - 32
        while (z == None or h == None):
            #11
            y = self.ExpandMask(rho_double_prime, k)

            #12
            temp = list()
            for i in range(0, len(y)):
                temp.append(self.NTT(y[i]))
            temp = self.MatrixVectorNTT(A_hat, temp)

            w = list()
            for i in range(0, len(temp)):
                w.append(self.Inverse_NTT(temp))

            #13
            w_1 = self.HighBitsVector(w) # w_1 = the MSB (more or less) of the Vector of polynomial generated by the public matrix times a (sort of) random vector. 

            #15
            temp = Mu.copy()
            temp.extend(self.w1Encode(w_1))
            c_tilde  = H(temp, self.Lambda // 4) # This is the hash of the Message Representative + tr. This is 32 bytes, 48 bytes, or 64 bytes long depending on the parameter set

            #16
            c = self.SampleInBall(c_tilde) # create a 256 byte array representing the coefficients in the range of -1, 0, 1. generated from the high order bits of the message plus some randomness the "Challenge"

            #17
            c_hat = self.NTT(c) # put into NTT

            #18
            cs_1 = list()
            temp = self.ScalarVectorNTT(c_hat, s_hat_1)
            for i in range(0, len(s_hat_1)):
                cs_1.append(self.Inverse_NTT(temp[i])) # create two vectors based off the two vector parts of the private key

            #19
            cs_2 = list()
            temp = self.ScalarVectorNTT(c_hat, s_hat_2)
            for i in range(0, len(s_hat_2)):
                cs_2.append(self.Inverse_NTT(temp[i]))

            #20
            z = self.AddVectorNTT(y, cs_1) # the "signer response"

            #21
            temp = self.SubtractVectorNTT(w, cs_2)
            r_0 = self.LowBitsVector(temp)

            #23
            # if the maximum element of z or r_0 don't make sense, loop, otherwise, make a hint and encode the hint, the
            # hash, and the response
            if (self.InfinityNormVector(z) >= (self.gamma_1 - self.beta) or self.InfinityNormVector(r_0) >= (self.gamma_2 - self.self.beta)):
                z = None
                h = None
            else:
                #25 - 27
                ct_0 = list()
                temp = self.ScalarVectorNTT(c_hat, t_0)
                for i in range(0, len(temp)):
                    ct_0.append(self.Inverse_NTT(temp[i]))
                
                temp = self.SubtractVectorNTT(w, cs_2)
                temp = self.AddVectorNTT(temp, ct_0)

                temp_2 = array("i", [0] * 256)
                ct_0_neg = list()
                for i in range(0, len(ct_0)):
                    ct_0_neg.append(self.SubtractNTT(temp_2, ct_0))
                h = self.MakeHintVector(ct_0_neg, temp)

                sum1s = 0
                for i in range(0, len(h)):
                    for j in range(0, len(h[i])):
                        sum1s = sum1s + h[i][j]

                if (self.InfinityNormVector(ct_0) >= self.gamma_2 or sum1s > self.omega):
                    z = None
                    h = None
            k = k + self.l

        z_temp = self.ModPlusMinusVector(z, self.q, self.q // 2)
        sigma = self.sigEncode(c_tilde, z_temp, h)
        return sigma
    
    # algorithm 8
    def Verify_internal(self, pk: bytearray, M_prime: list, sigma: bytearray):
        rho, t_1 = self.pkDecode(pk)
        c_tilde, z, h = self.sigDecode(sigma)
        if (h == None):
            return False
        A_hat = self.ExpandA(rho)
        tr = H(pk, 64)

        # this is maybe going to throw an error
        temp = self.BytesToBits(tr)
        temp.extend(M_prime)
        temp = self.BitsToBytes(temp)
        Mu = H(temp, 64)

        c = self.SampleInBall(c_tilde)

        #9
        temp = list()
        for i in range(0, len(z)):
            temp.append(self.NTT(z[i]))
        temp = self.MatrixVectorNTT(A_hat, temp)

        temp2 = list()
        for i in range(0, len(t_1)):
            t_1_i = deepcopy(t_1[i])
            for i in range(0, len(t_1_i)):
                t_1_i = t_1_i << self.d
            temp2.append(self.NTT(t_1_i))
        temp2 = self.ScalarVectorNTT(self.NTT(c), temp2)

        temp = self.SubtractVectorNTT(temp, temp2)
        w_prime_approx = list()
        for i in range(0, len(temp)):
            w_prime_approx.append(self.Inverse_NTT(temp[i]))
        
        w_prime_1 = self.UseHintVector(h, w_prime_approx)

        temp = Mu.copy()
        temp.extend(self.w1Encode(w_prime_1))
        c_tilde_prime = H(temp, self.Lambda // 4)

        return (self.InfinityNormVector(z) < self.gamma_1 - self.beta) and (c_tilde == c_tilde_prime)

    # Helper functions

    # Algorithm 9
    def IntegerToBits(self, x: int, alpha: int):
        bitArray = []
        for _ in range(0, alpha):
            bitArray.append(x & 0x01)
            x = x >> 1
        return bitArray

    # algorithm 10
    def BitsToInteger(self, y: list, alpha: int):
        x = 0
        for i in range(alpha - 1, 0, -1):
            x = (x | y[i]) << 1
        x = x | y[0]
        return x
    
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

    # algorithm 13
    # this is not their version which does a double for loop
    def BytesToBits(self, z: bytearray):
        string = list()
        for i in range(0, len(z)):
            string.append(z[i] & 0x01)
            string.append((z[i] & 0x02) >> 1)
            string.append((z[i] & 0x04) >> 2)
            string.append((z[i] & 0x08) >> 3)
            string.append((z[i] & 0x10) >> 4)
            string.append((z[i] & 0x20) >> 5)
            string.append((z[i] & 0x40) >> 6)
            string.append((z[i] & 0x80) >> 7)
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

    # Algorithm 18
    def SimpleBitUnpack(self, v: bytearray, b: int):
        w = array("i")
        c = b.bit_length()
        z = self.BytesToBits(v)
        for i in range(0, 256):
            start = i * c
            end = start + c
            w.append(self.BitsToInteger(z[start:end].copy(), c))
        return w

    # Algorithm 19
    def BitUnpack(self, v: bytearray, a: int, b: int):
        w = array("i")
        c = (a + b).bit_length()
        z = self.BytesToBits(v)
        for i in range(0, 256):
            start = i * c
            end = start + c
            w.append(b - self.BitsToInteger(z[start:end].copy(), c))
        return w
    
    # Algorithm 20
    def HintBitPack(self, h: list[array[int]]):
        y = bytearray([0] * (self.omega + self.k))
        index = 0
        for i in range(0, self.k):
            for j in range(0, 256):
                if (h[i][j] != 0):
                    y[index] = j
                    index = index + 1
            y[self.omega + self.i] = index
        return y

    # Algorithm 21
    def HintBitUnpack(self, y: bytearray):
        h = list()
        index = 0
        for i in range(0, self.k):
            h_i = array("i", [0] * 256)
            if (y[self.omega + i] < index or y[self.omega + i] > self.omega):
                return None
            first = index
            while (index < y[self.omega + i]):
                if (index > first and y[index - 1] >= y[index]):
                    return None
                h_i[y[index]] = 1
                index = index + 1
            h.append(h_i)
        for i in range(index, self.omega):
            if (y[i] != 0):
                return None
        return h
                
    # Algorithm 22
    def pkEncode(self, rho: bytearray, t_1: list[array[int]]):
        pk = rho.copy()
        for i in range(0, self.k):
            pk.extend(self.SimpleBitPack(t_1[i], 2**((self.q - 1).bit_length() - self.d) - 1))
        return pk
    
    # algorithm 23
    def pkDecode(self, pk: bytearray):
        rho = pk[0:32].copy()
        t_1 = list()
        start = 32
        z_length = 32 * ((self.q - 1).bit_length() - self.d)
        end = start + z_length
        b = (self.q - 1).bit_length() - self.d
        for i in range(0, self.k):
            t_1.append(self.SimpleBitUnpack(pk[start:end].copy(), 2**b - 1))
        return rho, t_1
    
    # algorithm 24
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

    def skDecode(self, sk: bytearray):
        #1
        rho = sk[0:32].copy()
        K = sk[32:64].copy()
        tr = sk[64:128].copy()

        #2 - 4
        s_index_length = 32 * (2*self.eta).bit_length()
        index = 128

        s_1 = list()
        for _ in range(0, self.l):
            s_1.append(self.BitUnpack(sk[index:(index + s_index_length)], self.eta, self.eta))
            index = index + s_index_length
        
        #5 - 7
        s_2 = list()
        for _ in range(0, self.k):
            s_2.append(self.BitUnpack(sk[index:(index + s_index_length)], self.eta, self.eta))
            index = index + s_index_length
        
        #8 - 10
        t_0 = list()
        for _ in range(0, self.k):
            t_0.append(self.BitUnpack(sk[index:(index + 32 * self.d)], 2**(self.d-1) - 1, 2**(self.d - 1) ))
            index = index + 32 * self.d
        return rho, K, tr, s_1, s_2, t_0

    #algorithm 26
    def sigEncode(self, c_tilde: bytearray, z: list[array[int]], h: list[array[int]]):
        sigma = c_tilde.copy()
        for i in range(0, self.l):
            sigma.extend(self.BitPack(z[i], self.gamma_1 - 1, self.gamma_1))
        sigma.extend(self.HintBitPack(h))
        return sigma
    
    #algorithm 27
    def sigDecode(self, sigma: bytearray):
        fourth_lambda = self.Lambda // 4
        c_tilde = sigma[0:fourth_lambda].copy()

        z = list()
        z_range = 32 * (1 + (self.gamma_1 - 1).bit_length())
        start = fourth_lambda
        end = fourth_lambda + z_range
        for i in range(0, self.l):
            z.append(self.BitUnpack(sigma[start:end].copy(), self.gamma_1 - 1, self.gamma_1))
            start = end
            end = end + z_range
        h = self.HintBitUnpack(sigma[start:end])
        return c_tilde, z, h
    
    # algorithm 28
    def w1Encode(self, w_1: list[array[int]]):
        w_tilde_1 = bytearray()
        bits = (self.q - 1) // ((2 * self.gamma_2) - 1)
        for i in range(0, self.k):
            w_tilde_1.extend(self.SimpleBitPack(w_1[i],bits))
        return w_tilde_1

    # algorithm 29
    # returns a pseudorandom polynomial with bits in -1, 0, or 1. This is based upon the input rho which is the c_tilde
    # in sign_internal, which is the message plus a portion of the private key
    def SampleInBall(self, rho: bytearray):
        c = array("i", [0] * 256)
        H = SHA3.IncrementalSHAKE.IncrementalSHAKE256()
        ctx = H.init()
        ctx = H.absorb(ctx, rho)
        ctx, s = H.squeeze(ctx, 8)
        h = self.BytesToBits(s)
        for i in range(256 - self.tau, 256):
            ctx, j = H.squeeze(ctx, 1)
            while j > i:
                ctx, j = H.squeeze(ctx, 1)
            c[i] = c[j]
            c[j] = (-1)**(h[i + self.tau - 256])
        return c

    # Algorithm 32
    def ExpandA(self, rho: bytearray):
        A_hat = list()
        for r in range(0, self.k):
            A_hat.append(list())
            for s in range(0, self.l):
                rho_prime = rho.copy()
                rho_prime.extend(IntegerToBytes(s,1))
                rho_prime.extend(IntegerToBytes(r,1))
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
    
    def ExpandMask(self, rho: bytearray, mu: int):
        c = 1 + (self.gamma_1 - 1).bit_length()
        y = list()
        for r in range(0, self.l):
            rho_prime = rho.copy()
            rho_prime.extend(IntegerToBytes(mu + r, 2))
            Nu = H(rho_prime, 32 * c)
            y.append(self.BitUnpack(Nu, self.gamma_1 - 1, self.gamma_1))
        return y

    # Algorithm 30
    def RejNTTPoly(self, rho: bytearray):
        a_hat = array("i", [0] * 256)
        j = 0
        G = SHA3.IncrementalSHAKE.IncrementalSHAKE128()
        ctx = G.init()
        ctx = G.absorb(ctx, rho)
        while j < 256:
            ctx, s = G.squeeze(ctx, 3)
            temp = self.CoeffFromThreeBytes(s[0], s[1], s[2])
            if (temp != None):
                a_hat[j] = temp
                j = j + 1
        return a_hat
    
    # Algorithm 31
    def RejBoundedPoly(self, rho: bytearray):
        a = array("i")
        j = 0
        H = SHA3.IncrementalSHAKE.IncrementalSHAKE256()
        ctx = H.init()
        ctx = H.absorb(ctx, rho)
        while j < 256:
            ctx, z = H.squeeze(ctx,1)
            z = z[0]
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
    def Power2Round(self, r: int, dpow2: int, dpow2_2: int):
        r_1 = r % self.q
        r_0 = self.ModPlusMinus(r_1, dpow2, dpow2_2)
        r_1 = (r_1 - r_0) >> self.d
        return r_1, r_0
    
    # algorithm 35 ancillary
    def Power2RoundPoly(self, r: array[int], dpow2: int, dpow2_2: int):
        r_prime_1 = array("i")
        r_prime_0 = array("i")
        for i in range(0, 256):
            r_1, r_0 = self.Power2Round(r[i], dpow2, dpow2_2)
            r_prime_1.append(r_1)
            r_prime_0.append(r_0)
        return r_prime_1, r_prime_0
    
    # algorithm 35 ancillary 2
    def Power2RoundVector(self, r: list[array[int]]):
        r_1 = list()
        r_0 = list()
        dpow2 = 2**self.d
        dpow2_2 = dpow2 >> 1 - 1 #(range is minus 1 because dpow2 is even)
        for i in range(0, len(r)):
            r_1_temp, r_0_temp = self.Power2RoundPoly(r[i], dpow2, dpow2_2)
            r_1.append(r_1_temp)
            r_0.append(r_0_temp)
        return r_1, r_0

    # algorithm 36
    # See power round 2 for the definition of mod+-
    def Decompose(self, r: int):
        r_1 = r % self.q
        r_0 = self.ModPlusMinus(r_1, * self.gamma_2, self.gamma_2 - 1)
        if r_1 - r_0 == self.q - 1:
            r_1 = 0
            r_0 = r_0 - 1
            return r_1, r_0

        r_1 = (r_1 - r_0) // (2 * self.gamma_2)
        return r_1, r_0

    # algorithm 37
    def HighBits(self, r: int):
        r_1, _ = self.Decompose(r)
        return r_1
    
    # algorithm 37 ancillary 1
    def HighBitsPoly(self, r: array[int]):
        r_prime_1 = array("i")
        for i in range(0, 256):
            r_prime_1.append(self.HighBits(r[i]))
        return r_prime_1

    # algorithm 37 ancillary 2
    def HighBitsVector(self, r: list[array[int]]):
        r_1 = list()
        for i in range(0, len(r)):
            r_1.append(self.HighBitsPoly(r[i]))
        return r_1

    # algorithm 38
    def LowBits(self, r: int):
        _, r_0 = self.Decompose(r)
        return r_0
    
    # algorithm 38 ancillary 1
    def LowBitsPoly(self, r: array[int]):
        r_prime_0 = array("i")
        for i in range(0, 256):
            r_prime_0.append(self.LowBits(r[i]))
        return r_prime_0

    # algorithm 38 ancillary 2
    def LowBitsVector(self, r: list[array[int]]):
        r_0 = list()
        for i in range(0, len(r)):
            r_0.append(self.LowBitsPoly(r[i]))
        return r_0
    
    #algorithm 39
    def MakeHint(self, z: int, r: int):
        r_1 = self.HighBits(r)
        v_1 = self.HighBits(r + z)
        return int(r_1 != v_1)
    
    # algorithm 39 ancillary
    def MakeHintPoly(self, z: array[int], r: array[int]):
        returnArray = array("i")
        for i in range(0, 256):
            returnArray.append(self.MakeHint(z[i], r[i]))
        return returnArray
    
    # algorithm 39 ancillary 2
    def MakeHintVector(self, z: list[array[int]], r: list[array[int]]):
        returnArray = list()
        for i in range(0, len(z)):
            returnArray.append(self.MakeHintPoly(z[i], r[i]))
        return returnArray

    #algorithm 40
    def UseHint(self, h: int, r: int):
        m = (self.q - 1) // (2 * self.gamma_2)
        r1, r0 = self.Decompose(r)
        if (h == 0):
            return r1
        if (r0 > 0):
            return (r1 + 1) % m
        return (r1 - 1) % m
    
    # algorithm 40 ancillary
    def UseHintPoly(self, z: array[int], r: array[int]):
        returnArray = array("i")
        for i in range(0, 256):
            returnArray.append(self.UseHint(z[i], r[i]))
        return returnArray
    
    # algorithm 40 ancillary 2
    def UseHintVector(self, z: list[array[int]], r: list[array[int]]):
        returnArray = list()
        for i in range(0, len(z)):
            returnArray.append(self.UseHintPoly(z[i], r[i]))
        return returnArray

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
            c_hat[i] = (c_hat[i] + b_hat[i]) % self.q
        return c_hat

    #algorithm 45
    def MultiplyNTT(self, a_hat: array[int], b_hat: array[int]):
        c_hat = deepcopy(a_hat)
        for i in range(0, 256):
            c_hat[i] = (c_hat[i] * b_hat[i]) % self.q
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
            w_current = array("i", [0] * 256)
            for j in range(0, self.l):
                w_temp = self.MultiplyNTT(M_hat[i][j], v_hat[j])
                w_current = self.AddNTT(w_current, w_temp)
            w_hat.append(w_current)
        return w_hat

    # no definition
    def SubtractVectorNTT(self, v_hat: list[array[int]], w_hat: list[array[int]]):
        u_hat = list()
        for i in range(0, self.l):
            u_hat.append(self.SubtractNTT(v_hat[i], w_hat[i]))
        return u_hat

    # no definition2
    def SubtractNTT(self, a_hat: array[int], b_hat: array[int]):
        c_hat = deepcopy(a_hat)
        for i in range(0, 256):
            c_hat = c_hat[i] - b_hat[i]
        return c_hat

    # no definition 3
    def InfinityNorm(self, w: int):
        return abs(w)
    
    def InfinityNormModQ(self, w: int):
        w = self.ModPlusMinus(w, self.q, self.q // 2) # q is odd
        return abs(w)
    
    def InfinityNormR(self, w: array[int]):
        maxW = 0
        for i in range(0, len(w)):
            maxW = max(maxW, self.InfinityNormModQ(w[i]))
        return maxW
    
    def InfinityNormVector(self, w: list[array[int]]):
        maxW = 0
        for i in range(0, len(w)):
            maxW = max(maxW, self.InfinityNormR(w[i]))
        return maxW
    
    # No definition 4
    # if m is even, m_2 = m // 2 - 1
    # otherwise it equals m // 2 (because python)
    #i.e. mod 9 has the range [-4,4]
    #     mod 8 has the range [-3,4]
    #     for mod 9, m_2 should be -4, and for mod8 it should be -3
    def ModPlusMinus(self, z: int, m: int, m_2: int):
        return (z % m) - m_2
    
    def ModPlusMinusPoly(self, z: array[int], m: int, m_2: int):
        returnArray = array("i")
        for i in range(0, len(z)):
            returnArray.append(self.ModPlusMinus(z[i], m, m_2))
        return returnArray
    
    def ModPlusMinusVector(self, z: list[array[int]], m: int, m_2: int):
        returnList = list()
        for i in range(0, len(z)):
            returnList.append(self.ModPlusMinusPoly(z[i], m, m_2))
        return returnList


#Algorithm 11
def IntegerToBytes(x: int, a: int):
    return x.to_bytes(a, "little")

def H(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE256().SHAKE(str, 8 * l)

def G(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE128().SHAKE(str, 8 * l)

#debug function
def PrintPKs(pk: bytearray, expected_pk: bytearray, q: int, d: int, k: int):
    bytesPerPoly = 32 * ((q - 1).bit_length() - d)
    
    pk_rho = pk[0:32].copy()
    expected_pk_rho = expected_pk[0:32].copy()

    print(f"rho matches: {pk_rho == expected_pk_rho}")
    print(f"length matches: {len(pk) == len(expected_pk)}")

    start = 32
    end = start + bytesPerPoly

    for i in range(0, k):
        real_part = pk[start:end].copy()
        expected_part = expected_pk[start:end].copy()
        start = end
        end = end + bytesPerPoly

        print(f"part {i} matches: {real_part == expected_part}")
        print(real_part.hex())
        print(expected_part.hex())





#H.Init , absorb, squeeze -> shake256

#G.Init , absorb, squeeze -> shake128

if __name__ == "__main__":
    # taken from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json

    # # "tcId": 1,
    # # "seed": "D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B",
    # # "pk": "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0BD77B16648A344FFE486BC3E3CB5FAB9ABC4CC2F1C34901692BEC5D290D815A6CDF7E9710A3388247A7E0371615507A572C9835E6737BF30B92A796FFF3A10A730C7B550924EB1FB6D56195F02DE6D3746F9F330BEBE990C90C4D676AD415F4268D2D6B548A8BCDF27FDD467E6749C0F87B71E85C2797694772BBA88D4F1AC06C7C0E91786472CD76353708D6BBC5C28E9DB891C3940E879052D30C8FD10965CBB8EE1BD79B060D37FB839098552AABDD3A57AB1C6A82B0911D1CF148654AA5613B07014B21E4A1182B4A5501671D112F5975FB0C8A2AC45D575DC42F48977FF37FFF421DB27C45E79F8A9472007023DF0B64205CD9F57C02CE9D1F61F2AE24F7139F5641984EE8DF783B9EA43E997C6E19D09E062AFCA56E4F76AAAB8F66600FC78F6AB4F6785690D185816EE35A939458B60324EEFC60E64B11FA0D20317ACB6CB29AA03C775F151672952689FA4F8F838329CB9E6DC9945B6C7ADE4E7B663578F87D3935F2A1522097AD5042A0D990A628510B6103CB242CD8A3AFC1A5ADA52331F4DF461BC1DA51D1D224094E7ABED3D87D98F0D817084780EE80370F397631ECB75D4264B6B5E2E66C0586B5FB743516399165837A0FDFF7C6134F033BFA69C1B2416965C6E578592F40E258CB6DFB29FB8E0F54355B6E24A65F67ABAE3193D007115CC0B9FF94CB911A93B1A76C0E7662F5E2B20139E0159ED929CB932D4895F89A02E55C59DF2DBB8F6E5DD7D5B1F3CEC37B4A9166B381C5440E23E67368CDE0A29D59AA05A3C9BE24A4DC8DD75BE30E82BC635D36AAC66DE880C6701A987D7E05F0F2FF287828BEC30595089D8AB9AA390ED719CAA6E576CDBBE9B184A322E5E2DABB69C23CC696D54FC32FF57001B6B64E2A837F3062D85AEB50B3510F7EDFC34DF38E083D4D9B94FFAB0DE15D73D9AF30B9F31CC4F41C9C24F2D618B2A7C3C4BDFB745D52D3EB54589C8BDA8AC05DAD14EC744505575A0988EEC651C1715439FDFB29923380A43C1A66A86C982A841F11820A6A0E1E2F2FFF5108ECAE51A6AABC9B949226D228FF84C4E5E5D63114D80359C4931E612DCED1838B7D066AC9182CECFA223A21A4C8E155AEFA780373BCC15098AEE40C033AF22F8E7C67A0D2526DA7475E830308C04AED9D32BCCC72E719EE70A8D13F09AC11E26EA237D5CC8F98B5AE0E54F933BD0507942ED900D056FD32F8E6E81777912FD482746029B71CCE3BA69B8FC2D03EB441027C387BC2F95031A0AE7052215EB24B9EA8FB0A961B0F80BFA80D0D6257C1C22B508C5D31B97FCDFE1D1766E8A9C8771932DD598ADB7E717743F45FC571F21E4A516249F81D747F15329790F0F70A0B8E461A4EDF50504AF03F30DDF8A8818E38761E1681D6DDEF0B1DD326B2EC228CE48570F285B49D29D7C2EF37866D5446DF82B8E43B34CB248962A21A9A3946159740F8AEE8E6A16A4EB2B42D143FE2612E05EF4B5E646D813248444556A2A8BF92CE10BADECB6B8A40B080DD42D53346FEFCC4B9B40B1E4998991EC753C95AA2F2A506F311E710B0F1D36C1DCA6644EE6D1D4AE9CEA5666EF4B3E888DBDBB95A77ECFE1E8B477DE7CB07639D682D53020EC14EA6C7DD7E715389D10938429FAB8A068A1466A4CD891359F8074E0F5A142ADD731B87878D985E4FA6ECB3B73D298553418273E9503AA84092C080E5F2902F90F5C59944D24CA0271D11D0D6734606D039550A37FCA2B735850E63F540F2F06B79144B5C4ED2C700BB51C33D265B3D037389C99EFD597642D829DB1EB58643CFCD07F4DEC60B8F727D97BD7C4B59BDA1",
    # # "sk": "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B28965F58D99EE0DE7BFB7840F59F65414289E259E05E8A18D47EC06D7900284AD7A0AE404B93B0498945ABD07638920FC7F8C21282031EECEB0CC48D71FB0AD1CE84B9B3DDD1B3A2A40A15D5BFE0BE23FC4757137C6C8FEB7F8055677BA4AF2814242A9AA0108A4046981800042130A2340A99140E01A931E1300A1A136959486601C111140451244206E4C848A1B80008B2490121901224500B03306112025C144912B30049424D14470E93342023898803238CA1C081CC0411184545C1C20862465210300D52B870A3B004DCA20D4A386511214A01B48C43104809461253068161348618A00920878CA0168682208E41188E52A29021014652184521A42902132ED0B8248816710AB245818480942670DC126C1BC16C4016246236008996108B124E1B3721639225E1C88CA346285A32111C856110B9295990910493651CC40063B810C1184A52900C1CB20D2380090A4021D4188043A64D0835060C98650CB4890C8661D804601C0789D09231D8081100881119294E48B661D8962DD2B04121A1051226860349301A246D99483001200C5CC2840128900A298850340E1804640AB409D1968413196DD91031133689808025E300294A06304448109B429008858902A20D13461110120EDC380C4C468842C004131490C1462248B82D48C80D64346C02348109136842A4211B26511C302A6328688B18609C922C22C9000031058AC08C894430D0142189424C4C106400B64DD2A8246306308BB4289B246EC34262A0C00C0C2050E112444A360AD122320C36014836804C00400C16090C9569A19829110602CC982D08C811498445D20290014942C1062E42C000A2902D9810711A054008058608B2651B36441109402107100B3306D298858148088034305C3844DC266ECA947004394A442841E1464898862D113621221509530826213088DA94804A80601425321295641B02120A92241A4422230624CC12818922600036608A32820CC368A1A04D5B286A110744589851C42831A4064EC0C831CAB46810B669132488840462A3C421E0920523303050B6105942285C3005102286CC260E2226450003928A242C9C024E40B20400148C4A086E4BA6444CC84924464D4946821AA4690A316E21408C22964949044618B72C12B864D1C851C3366E5C2008E3328513198564C2019A4822111300A4B64960C06D1944628C086119B761021570EA732640984F68143D81AB95763698DCD02625A980994C19B7D47626409370F87E45D39B76B6762F7827B2779BA44046F54228A7B1BAC9D8E751AC2DD248521564F81D028AD671DB6A3A5BA3A9463597A519AE0C1DA435FEF7C421CDE7F8483782C4334993192923796DDC3E5803F6C86CF2B37E39BBCB53775E5E9D2BDC65E84395B01AF95C4398503A7E63A8D72F7E9BC58D7655CB86BAFA0B679D1D791F09703F6E4B333A51DFB14B36EAC9A3582F795AFCECC2A67A42C7BC43B447B73EC8B73C9164B2D9EF4F767D607E975738E1D871FE61B7BB9570516959B9E7D8155455FC91590D84BD430921568B718241CCD09C989DDF75F529C4F15818969216EC0FBABEC64F184832BFE428BE44849C42F13CA84A5CE6CA628044CB9DA3FD9CB5EBC776BA0E12683B98253B213B286593779EACC489C985BEB734A7506791BE1A6E6E03B557CFEF2069091B846CDBBB72D36A89FD5C45C7C7FBFAED956EC9D8F3025225D6FEF811B1CC3C6705F056388BBFBBA1FEBF4D072281DC792ADA048216D60D0D6044150909B70A4753336F4D5D3FDB8BACA62946DB28332EC778A76F96577BAF868BF896773C200637495098B0F7749835915348D37641EC74D5A78E565D8100627468B0B5D05C2937618A98E5A12476533CE9D699E0F4F23B3127EE1F8D3CDE3851A94BEB8D606D836D47A9F090581B660FF8EC31E3EF4E45DB530DD88A44D48F84B6BD3CED53BE935EFBCE9930DD83BD004F086A064B3260B7211BA0547CB29E56603B922597B31A30A5FFCBD8A7AD2F3F05372DCEA89048C683164410E56A6E5B7EC2EA6E3B0176DB1EBF9258C97C297E752A202B1B4B02DA47235873CC3E4A376B655779AFFFC9AEF2E30B62BE022AEFF5E34B468507C921A00F1110B2CC1BC99B2EE295A31EAC141AB4D87EDC11D7FEE22A07D69B7008C107EBE47DD2F215D074868C8B929A3DF6614B5E95CC8A52F96C57E1697CEE332F45B1980E6CA372574BDB51825654E6FF31D8E755CFC15B602F46A0570D3BD0D65E43BDE8F792E7D526B3D362FE33638B3870E1C29E1030D3DBA43C3D0DB6E5F501EA3441B709E54FCA1FD3E8654B1A9301AD151A36C8FA1513D0229DE6E94D02A97B9D6F2EE8078A5D1228E783B8FDAC46102A19600C531276B447F3900EF8F723FC3B60D7BBBBDA9F949E4460B2F1103315ACE25B3497CA4B4674A6052304609A16E90D064B0F6A9EAE8D8E4BE38E3B781F9173654E876CE6CC00578171FD9CFDBA5704AF2E60CF84FD02EBEF19AED140287D195023000568E8D908EDEADC76BCA3E7FE8FE1F4B201C2A15603C025A61917AE664B4294C57030AC988D7967364A8BB5857E98218C2943E8CF1CB8C719DACCFAE8F42AA7DDE9B4130170068A9CC86B0552D1DD0A48F63DDB8F8A51B3C0E10F3174A87D18F96533CF0C30C0BE33D37C25CD3EBF8F5F10E66464AC2FB8260BA8B5BD443ABC6AE0D5F89DAA42BC71B2A9BC2D10140B117E32F41353FA1ECEC9DBCCB621350806C4E4EBFC966AA7122D85532728EF26AA40E55E2E1739790FFA157EFA4E2A68DA1EA4C9E3273CDE11DB7DA47220123C40D50B73B8460CD93CB449783EAD8A58F6FF272275A4F6C0437DAF3DF1D8D9617743D9302E73B715AA7CAA139CDD07EDAD2DE7B32B3F11E3C2B6A96D4630632C6D1DE21473A287D42B52D210CD4EF808A998148817BB5083BDAB3A3354B084C5773970B15DA56F755E1F25354EFEFF89FDF4E307998D623CED32C7B9E942B6816A87A233867E2BEB84582FFF61AF612BE6E521AB3005E17D471A5C67A0A927211802CA4A0C2FEDC01A12AF5E8A6E8FF7BD08883AF1D35C2F8570091D9E5FCD9D720644F0A45042443D2FAC309FA7A15B2DBBA1517EA19407B17CAF7E9EA81FBCE42F35A0568B2F70B279E12DA48858F0E0FF0B5CB3A3012308AB83DB627F5439E3A424D83F9E0B7750F2CBD9CA4AFB9BA77765A1EA590CE9E37BC7EABE1EF099765CE59EA74C2776ECCBCEB895997F577733C609B9E853CF03010C5B9CC4E819C041ABF11A9B3866502BF6AC0354E6CE1060D5155E6E5A1AC4FADF73080B20569317F9E118B97C78D7273300E329373E5B64A4181C4AC7B8933F82ADE505D52CDDCEBA373A54D072BC04A8D83273586615ADDC4D6F258BFD75AE94EFD120F20B721A1CAC33FF3446E554D6CFE266B05E4CD44DE77D263A9D347F53B282A7BCB1511DD405A67AC05E7233F5EBB40D38F953AC903F90E96F17A6357EB59ED7900FFD82F54C3043D37F7774A0F4DEFAF65887EB53FE156FB26794982B1249BAD27C89C136097AA2268347FC9C5E5BE79E23C923215353A850E63748E766"
    # x = ML_DSA(ML_DSA_PARAMETER_SET.ML_DSA_44)
    # seed = bytearray.fromhex("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B")
    # expected_pk = bytearray.fromhex("B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0BD77B16648A344FFE486BC3E3CB5FAB9ABC4CC2F1C34901692BEC5D290D815A6CDF7E9710A3388247A7E0371615507A572C9835E6737BF30B92A796FFF3A10A730C7B550924EB1FB6D56195F02DE6D3746F9F330BEBE990C90C4D676AD415F4268D2D6B548A8BCDF27FDD467E6749C0F87B71E85C2797694772BBA88D4F1AC06C7C0E91786472CD76353708D6BBC5C28E9DB891C3940E879052D30C8FD10965CBB8EE1BD79B060D37FB839098552AABDD3A57AB1C6A82B0911D1CF148654AA5613B07014B21E4A1182B4A5501671D112F5975FB0C8A2AC45D575DC42F48977FF37FFF421DB27C45E79F8A9472007023DF0B64205CD9F57C02CE9D1F61F2AE24F7139F5641984EE8DF783B9EA43E997C6E19D09E062AFCA56E4F76AAAB8F66600FC78F6AB4F6785690D185816EE35A939458B60324EEFC60E64B11FA0D20317ACB6CB29AA03C775F151672952689FA4F8F838329CB9E6DC9945B6C7ADE4E7B663578F87D3935F2A1522097AD5042A0D990A628510B6103CB242CD8A3AFC1A5ADA52331F4DF461BC1DA51D1D224094E7ABED3D87D98F0D817084780EE80370F397631ECB75D4264B6B5E2E66C0586B5FB743516399165837A0FDFF7C6134F033BFA69C1B2416965C6E578592F40E258CB6DFB29FB8E0F54355B6E24A65F67ABAE3193D007115CC0B9FF94CB911A93B1A76C0E7662F5E2B20139E0159ED929CB932D4895F89A02E55C59DF2DBB8F6E5DD7D5B1F3CEC37B4A9166B381C5440E23E67368CDE0A29D59AA05A3C9BE24A4DC8DD75BE30E82BC635D36AAC66DE880C6701A987D7E05F0F2FF287828BEC30595089D8AB9AA390ED719CAA6E576CDBBE9B184A322E5E2DABB69C23CC696D54FC32FF57001B6B64E2A837F3062D85AEB50B3510F7EDFC34DF38E083D4D9B94FFAB0DE15D73D9AF30B9F31CC4F41C9C24F2D618B2A7C3C4BDFB745D52D3EB54589C8BDA8AC05DAD14EC744505575A0988EEC651C1715439FDFB29923380A43C1A66A86C982A841F11820A6A0E1E2F2FFF5108ECAE51A6AABC9B949226D228FF84C4E5E5D63114D80359C4931E612DCED1838B7D066AC9182CECFA223A21A4C8E155AEFA780373BCC15098AEE40C033AF22F8E7C67A0D2526DA7475E830308C04AED9D32BCCC72E719EE70A8D13F09AC11E26EA237D5CC8F98B5AE0E54F933BD0507942ED900D056FD32F8E6E81777912FD482746029B71CCE3BA69B8FC2D03EB441027C387BC2F95031A0AE7052215EB24B9EA8FB0A961B0F80BFA80D0D6257C1C22B508C5D31B97FCDFE1D1766E8A9C8771932DD598ADB7E717743F45FC571F21E4A516249F81D747F15329790F0F70A0B8E461A4EDF50504AF03F30DDF8A8818E38761E1681D6DDEF0B1DD326B2EC228CE48570F285B49D29D7C2EF37866D5446DF82B8E43B34CB248962A21A9A3946159740F8AEE8E6A16A4EB2B42D143FE2612E05EF4B5E646D813248444556A2A8BF92CE10BADECB6B8A40B080DD42D53346FEFCC4B9B40B1E4998991EC753C95AA2F2A506F311E710B0F1D36C1DCA6644EE6D1D4AE9CEA5666EF4B3E888DBDBB95A77ECFE1E8B477DE7CB07639D682D53020EC14EA6C7DD7E715389D10938429FAB8A068A1466A4CD891359F8074E0F5A142ADD731B87878D985E4FA6ECB3B73D298553418273E9503AA84092C080E5F2902F90F5C59944D24CA0271D11D0D6734606D039550A37FCA2B735850E63F540F2F06B79144B5C4ED2C700BB51C33D265B3D037389C99EFD597642D829DB1EB58643CFCD07F4DEC60B8F727D97BD7C4B59BDA1")
    # expected_sk = bytearray.fromhex("B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B28965F58D99EE0DE7BFB7840F59F65414289E259E05E8A18D47EC06D7900284AD7A0AE404B93B0498945ABD07638920FC7F8C21282031EECEB0CC48D71FB0AD1CE84B9B3DDD1B3A2A40A15D5BFE0BE23FC4757137C6C8FEB7F8055677BA4AF2814242A9AA0108A4046981800042130A2340A99140E01A931E1300A1A136959486601C111140451244206E4C848A1B80008B2490121901224500B03306112025C144912B30049424D14470E93342023898803238CA1C081CC0411184545C1C20862465210300D52B870A3B004DCA20D4A386511214A01B48C43104809461253068161348618A00920878CA0168682208E41188E52A29021014652184521A42902132ED0B8248816710AB245818480942670DC126C1BC16C4016246236008996108B124E1B3721639225E1C88CA346285A32111C856110B9295990910493651CC40063B810C1184A52900C1CB20D2380090A4021D4188043A64D0835060C98650CB4890C8661D804601C0789D09231D8081100881119294E48B661D8962DD2B04121A1051226860349301A246D99483001200C5CC2840128900A298850340E1804640AB409D1968413196DD91031133689808025E300294A06304448109B429008858902A20D13461110120EDC380C4C468842C004131490C1462248B82D48C80D64346C02348109136842A4211B26511C302A6328688B18609C922C22C9000031058AC08C894430D0142189424C4C106400B64DD2A8246306308BB4289B246EC34262A0C00C0C2050E112444A360AD122320C36014836804C00400C16090C9569A19829110602CC982D08C811498445D20290014942C1062E42C000A2902D9810711A054008058608B2651B36441109402107100B3306D298858148088034305C3844DC266ECA947004394A442841E1464898862D113621221509530826213088DA94804A80601425321295641B02120A92241A4422230624CC12818922600036608A32820CC368A1A04D5B286A110744589851C42831A4064EC0C831CAB46810B669132488840462A3C421E0920523303050B6105942285C3005102286CC260E2226450003928A242C9C024E40B20400148C4A086E4BA6444CC84924464D4946821AA4690A316E21408C22964949044618B72C12B864D1C851C3366E5C2008E3328513198564C2019A4822111300A4B64960C06D1944628C086119B761021570EA732640984F68143D81AB95763698DCD02625A980994C19B7D47626409370F87E45D39B76B6762F7827B2779BA44046F54228A7B1BAC9D8E751AC2DD248521564F81D028AD671DB6A3A5BA3A9463597A519AE0C1DA435FEF7C421CDE7F8483782C4334993192923796DDC3E5803F6C86CF2B37E39BBCB53775E5E9D2BDC65E84395B01AF95C4398503A7E63A8D72F7E9BC58D7655CB86BAFA0B679D1D791F09703F6E4B333A51DFB14B36EAC9A3582F795AFCECC2A67A42C7BC43B447B73EC8B73C9164B2D9EF4F767D607E975738E1D871FE61B7BB9570516959B9E7D8155455FC91590D84BD430921568B718241CCD09C989DDF75F529C4F15818969216EC0FBABEC64F184832BFE428BE44849C42F13CA84A5CE6CA628044CB9DA3FD9CB5EBC776BA0E12683B98253B213B286593779EACC489C985BEB734A7506791BE1A6E6E03B557CFEF2069091B846CDBBB72D36A89FD5C45C7C7FBFAED956EC9D8F3025225D6FEF811B1CC3C6705F056388BBFBBA1FEBF4D072281DC792ADA048216D60D0D6044150909B70A4753336F4D5D3FDB8BACA62946DB28332EC778A76F96577BAF868BF896773C200637495098B0F7749835915348D37641EC74D5A78E565D8100627468B0B5D05C2937618A98E5A12476533CE9D699E0F4F23B3127EE1F8D3CDE3851A94BEB8D606D836D47A9F090581B660FF8EC31E3EF4E45DB530DD88A44D48F84B6BD3CED53BE935EFBCE9930DD83BD004F086A064B3260B7211BA0547CB29E56603B922597B31A30A5FFCBD8A7AD2F3F05372DCEA89048C683164410E56A6E5B7EC2EA6E3B0176DB1EBF9258C97C297E752A202B1B4B02DA47235873CC3E4A376B655779AFFFC9AEF2E30B62BE022AEFF5E34B468507C921A00F1110B2CC1BC99B2EE295A31EAC141AB4D87EDC11D7FEE22A07D69B7008C107EBE47DD2F215D074868C8B929A3DF6614B5E95CC8A52F96C57E1697CEE332F45B1980E6CA372574BDB51825654E6FF31D8E755CFC15B602F46A0570D3BD0D65E43BDE8F792E7D526B3D362FE33638B3870E1C29E1030D3DBA43C3D0DB6E5F501EA3441B709E54FCA1FD3E8654B1A9301AD151A36C8FA1513D0229DE6E94D02A97B9D6F2EE8078A5D1228E783B8FDAC46102A19600C531276B447F3900EF8F723FC3B60D7BBBBDA9F949E4460B2F1103315ACE25B3497CA4B4674A6052304609A16E90D064B0F6A9EAE8D8E4BE38E3B781F9173654E876CE6CC00578171FD9CFDBA5704AF2E60CF84FD02EBEF19AED140287D195023000568E8D908EDEADC76BCA3E7FE8FE1F4B201C2A15603C025A61917AE664B4294C57030AC988D7967364A8BB5857E98218C2943E8CF1CB8C719DACCFAE8F42AA7DDE9B4130170068A9CC86B0552D1DD0A48F63DDB8F8A51B3C0E10F3174A87D18F96533CF0C30C0BE33D37C25CD3EBF8F5F10E66464AC2FB8260BA8B5BD443ABC6AE0D5F89DAA42BC71B2A9BC2D10140B117E32F41353FA1ECEC9DBCCB621350806C4E4EBFC966AA7122D85532728EF26AA40E55E2E1739790FFA157EFA4E2A68DA1EA4C9E3273CDE11DB7DA47220123C40D50B73B8460CD93CB449783EAD8A58F6FF272275A4F6C0437DAF3DF1D8D9617743D9302E73B715AA7CAA139CDD07EDAD2DE7B32B3F11E3C2B6A96D4630632C6D1DE21473A287D42B52D210CD4EF808A998148817BB5083BDAB3A3354B084C5773970B15DA56F755E1F25354EFEFF89FDF4E307998D623CED32C7B9E942B6816A87A233867E2BEB84582FFF61AF612BE6E521AB3005E17D471A5C67A0A927211802CA4A0C2FEDC01A12AF5E8A6E8FF7BD08883AF1D35C2F8570091D9E5FCD9D720644F0A45042443D2FAC309FA7A15B2DBBA1517EA19407B17CAF7E9EA81FBCE42F35A0568B2F70B279E12DA48858F0E0FF0B5CB3A3012308AB83DB627F5439E3A424D83F9E0B7750F2CBD9CA4AFB9BA77765A1EA590CE9E37BC7EABE1EF099765CE59EA74C2776ECCBCEB895997F577733C609B9E853CF03010C5B9CC4E819C041ABF11A9B3866502BF6AC0354E6CE1060D5155E6E5A1AC4FADF73080B20569317F9E118B97C78D7273300E329373E5B64A4181C4AC7B8933F82ADE505D52CDDCEBA373A54D072BC04A8D83273586615ADDC4D6F258BFD75AE94EFD120F20B721A1CAC33FF3446E554D6CFE266B05E4CD44DE77D263A9D347F53B282A7BCB1511DD405A67AC05E7233F5EBB40D38F953AC903F90E96F17A6357EB59ED7900FFD82F54C3043D37F7774A0F4DEFAF65887EB53FE156FB26794982B1249BAD27C89C136097AA2268347FC9C5E5BE79E23C923215353A850E63748E766")
    # pk, sk = x.KeyGen_internal(seed)
    # print(pk == expected_pk)
    # if (pk != expected_pk):
    #     PrintPKs(pk, expected_pk, x.q, x.d, x.k)
    # print(sk == expected_sk)
    # print()
    # print(sk.hex())
    # print()
    # print(expected_sk.hex())
    # print()

    # # "tcId": 2,
    # # "seed": "AB611F971C44D1B755D289E0FCFEE70F0EB5D9FDFB1BC31CA894A75794235AF8",
    # # "pk": "D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA18056264432056C416013F5AFE21ADB7F4A5CECA1EE694E580301B47EB634E18C25BC0C964470BEBF10AFDF7587BAE7FC40D45F94519A661A7CD04F7AA0D95AAEE797027D8CBFAEE682ADD859106CCA978F5311A3B53A1699691C1E9E8BF9D2118B23BB1B33C5E9A02F968C800560A865FB826289FB34C936C825D1D0A7DB566B9F30B8E42E7A9AE8F325E51C197CEA36DDB79DF537D1F4102DD44C01B59401770BCCF4D5E8329121863929C91DFCA9C00F862ED7DBF3CF7558F6150B2B05D32F04C1E6E775350248DBFC0AEE58681B5B177CA7BA17ED6C7B4BA7302DC0F349564DB0D83C7F7D1AFE502E27DC465704AA9B7AA50D8F5A14CCC5701FAE3505D3AE11EAD8142AF9EE7991B3B216686126627C60E1769EC805000A6D94076905630D385B7CDA7195B54522A81E8855F3D6DAC03E686CADF72A9142363770283915034ECDF9047F80A8F9594273C7637B514BAF9ACE79A7B5D28F8B0EFD63A1F8B17301F499FD37E448F5E99F118FC7B2A4BFD7DADA350456CE5CC72C5646C57229ECD91082A85EFA259E2AAFF761F0A101A2269C8B88D94F7A8E4F87E7B9F977396E71BCD2B2BF89AB8B829A345D37FE5240CE7216C64EFB01BA8A13700D4BFC9856EACE22FB763BEC7D1E02F0F49B45F587BA6B3F571BE7AEBEA88557492C6C766D7AE298C7902F346DEDA494EEAC39C8767199252C9CE18825385596956F1F41B2BB534F761FA0C89917077B23F8056AA7405F8AE4271B11DF284D4FF50AFCDBFDCBE880131B60E3534091A759531FBE6E14D6057BDB458449AE4BCEC26580877331359E794E9D75BF454122264CCD13F9349C8250F0BB586B5BB482EB74524FD12F0F61EDD28411D072FCEC556BBC5569AFCEF1A62C26078088A77ADA5976E6A2A99E98C898E5789DE786B45708271957D88594DB7FBABE23DDBF1ABB12E715BD576483EAD259BA6553E95AE65AEDB55751532B98F32376BADDD2532E5801A255FA6DFC3FCCD5FC5110EE231450DDA25C4E09B89B577B8589C7179B06D62ABA652BD6DAD5159E8D7B84A5879F075EBD31ECCE03D2F1E508FB229665B4232B905638176AFCF232D4C19AF38A812C8D2AF2776CD444E94D46816EE68E7B5CD5AC1622518682EEE88E0F64358181EF35A8EC71E00E70F1222F494615A4FDF7C769CADB0E13B2F15B5EDA38809A5960D25090C1513636DE242BBD9A79F77CB45C81557D6F1D18991B37BECD4CAD9707B1F88920B69A55CD52CDAC2318287D4B13BC9CBA6884F9A38054493BDF91B29C2B7A71E2DD8ECFCDD0259BFFF402251CA2C95042AF917EBB669ACE5B354DC393A10F66847D546C47EDA695AD3A985834292E68A024AB6045ADF36DD2A58993A292B24837F61711CB59EA8DEB103F63F971E385CE0490A0709C890CAF57ED86991ACA729DBEFEB023D4356B7144485B7AF45559C3FF722EC8FCD8BEFBAF41119A24C9B686A79C38356F3FC55720F03AC89B3187CECC0C1247B9F8DDD82B8B415BAA6BC7A25E2529C41CC9765C768DC6A555D6114707879E810BC4C7472A07E8B90B0F41B8B4CABD5326B190572B664127E2FB476D88DB32D42D50BCD7F637AB2B7D13E0A7D03DFA30B0B81F7D2917C1CA5260BF71230F7342A5BB9F9261D966CDEE85F768A9B8B509F094C60E0C08BAC278827E84E6590141FF8C10E9B51FBF6E7724030EEB8B59731E47FA3D130407F833455386B66CBC453FF4BACC0467D747A1037EA57B3DE4421C3050DC6D33268CABE633C6E54C13D64973751798A99D8C53A2132E5BBBF8B2961B9E800F01940C700E47E4E1",
    # # "sk": "D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA180565499F298E78451161F0E9FF4B862815F3D5D33393AF3E677EE2460DF7BF3AE6E9A80F12A9B349DFDB9B3D0513BFFE620394A80A2883BCC69F1847057AC3BF35E63A72E60D5267D606C524AB847BCBC1113874755248DFBE583A2F0DB0FCBC8CD9C9008128028CA962CA038680919464C008ACC084D00466093002A541631D9A890D21200DCA8515418655C2005C8306A0C01204B040E1C913001418C11448C1A3206CC060C50B27058244593A0119822012426260B402603090E5A12020301611A14010119625222200CA3650B09904AB44D80264D5A366263906D1207320339491036111223041888202421880AC82819806C492629C4922062188993367204220282086558945018B32823335263A20112498C91B428E4C645DB82694B021101270A09397220314042A44DD23092913444C134091946200C210D4B36101026111437699440895308204324019B464152B8854286891B11880C41449C3252D2200520320C13948510930582C6480211865B262CCC884444B42DD2088E601062CCA66D8344451B3765C8B05180066922040CA40489514424A3404162965019C78160320D9816921220101915016248051C362E59308A13126AA3444610A52900C98C93C4100BA04508170558486201086C183392DCB86DCCB08D59906420026014B309104945A3A60012472E1C005203C91003492C1C92811B396613465001294650208462106900255043B8201CC68D981284A03204220821DBC46CA10622A09071E4204D213984D4B44023432401B6001A318289188209067112B131C3B624CA126C90066201036C0825909B3669E28044982428C4B0100B384159986D4B220118382618332E11150C49A8088C48898BC62862864C00461224A681C3C681E0C60D19046E9C9441C1283203466E1321251CB5854AA084A424319CB02048946014B7404814501319691AB00012B12413C880628410C31061D94040DB4806898869119289149700C204241CB7058422284B3646130132CB406160140CE0005218010A50228118278013329004269110A32C99B42C5C44464B3632DC468A49B04858884961C44102A2650302624326410B9885A11426481092DA962898C8006028104386688342254412102343511C326A09884511C5654010065BA001CC32889922258A1666420611898241120165C3140621446C09450149424C99948C0045022C7B04EF5AD7D8FD0179FC8AFDA5DCADA47CF7926345F6CD5F072625345A613C92D8D1EA7CFD213DFCD7896567194767DA47E3B3BED4E3F2CF727C78F7FD63855CC68EFEA538728CB803830B6FC646A865B93A46CB4EE30968C8A61D913DACC0483CC19DD790ACEC8E07BA8F5E924D7F024B69552ECEB588A94DC2BF11BE97A59A8065043525C628B59CE423CCF8293C78363C98662EE883F8B46A243AB2AB8ED3EB24C4AFDF383B2E9F0F969D4E6DE19B06BF6837ABDF751725B97D45389138EDB253A78C78DE841224FD7CFFAE2D8D58FF5D9B9ECD9C209F77CCA5D167B1A93EC5A9B891E1E4DBF1741DA1C4AAE7622B15F040DA03350CECF2649E309D38A8D5F8AA218900F321557C593DCB83A6A5A2C3C13129A07236E6F50864E4E9E11B840F3D6E6B74ACFE7394DAD62167E1CAE165B9207596B1C7CD3DE62558C24723C8F74BB4203F0F5272D0E1E8EC631BEC8ED97E9DC58FC843A901329D566A3A230D138B3AAC9B29CCDBEFDD2A6AAA7AC2C57A4850AB0AE2425D5A1F572848755D8894222F37885C8D7D34C02FA95457C7EBCF1D56B3361DAAF75F43399CA1958609BF9654A0E50C6AC0B405014AB252767A8C31F9D23BF9DAE2FC6A2548215B9E77F2FD28D049232763109367B1AB9A25DBAE50ABDA2422A8F262A5A19D4035FDA91433072E5E1DC927425EA3D1DE222230889373EF0D08E475662B6BEBDF6C4E48AE442331D9C7FCBCA2C41901543AEFECB866D132090AA366A358939EF9AFA92B533A60444C95BB50EC36DC0478F4511948E34A4A2EE53B439EECA84B53B3470E86413C04822CB6209FFB97C777DA0BE08F46F629DD64BE853901BCF32D1BB5EFC5512B0AC678154E98E862A9DF088243A1E279C55253AA3666AB343909B2421917FAF7FB4AB09A0268D3BE0CC9DEA933375975EC7E3AC22E50CEB3BE9FB3549EDF77D129FE75B1D24C2BECDBCD734F6A03349A4EBE17323985A9FFE33C1F68E99F321B3EB918C0BDE1A53A79906BD5704351693AAF92804310DF2A4F05E1EAAFC241C308ECE274B9B09935D5889EA1F58F580D2CADD2F9F9712279F0FA1F8AE4AEA4D993C55CE420DDFE5527FD0ABCEE4FC8F547F6C335BF6BD6827CCA513567CF4744CAAC1C373B8F8E12E2234B0341F7F3974BD9A2079EB5C48F25CF6400A1299E42F2D77804433E182F8EE02A1966846152FDAA949B9979260D1B511FAA2A705A2282E3955B6B906A2FAA28FD054A9B78E424FA5895650E60A2B1BEB1AA6480EBCC0A01657A8344AB896DFA7C023DEDA05EF642134A3AB9A783DA9AE6D189D2E2C2574ED909D757230885C0155644F25166A0474F618FBB5066446C7091D6E6E7EFAA6890D3704F8FF5170F2E2F656FC7825C2F1175A8DE14EC4CDC9F7D4D0996199D63C44E53D8ADB961335C954462B19B9BF52A67E3DE2BE220156E4DC9445904FA9CF42C2DE922231FF1BE379830ABF6F00B46A79F470E2A4471730CB8C29A000EBEBE10A2789A714F07F432962827AF53B321B8F7DE08A95D47FFC223DF9A44EE0FED3D5BCCCD948420E4E8D452AF900D49C022A3FB6C0D6887C836393597E40D36613E77CCD8A306A21CF826D20D9F823513815D885EB74F04ADEDA4051BD0998F7C9A48015BF662D72F6A99AED192C283D936E65F48E9748ECF2E0325518EF4F4B6991BC3956F3954535218B3727A721E31DAE286AB9947F13CD59E8F0FE7214DFB1540731049216D8069DF7A2BE167623684D142F721444204DDBAA851629A43DD9F75554ECAC9BC397C497B9097F85403DB3F6DD8AE83E4B0DE698F5E0AEF23FBCC21167E10EF554791F87DC9BD58F8EE82AF76B0846510873159A534E129DAF7B567BC17D5EE78C9630EA506DBEDBA84E2D1FC5DF9154903038A0FE8EF6C3AF6028D71CB2CF593596316A989A28DB6CF1814999DE9F597ABD1ABC20A168E2F2FC12F5C3D04D3581E0DF9CC2F890C207F97861790E0D1CDC67590DEEC5C6E9BA3EC2FB2AA3F0F047FE210CBE8EB03CC5F976A74DF9EC1086CD4D1A9B8E47888BD77095C305852E02C85F5B9BCDD6FF1C2B79E299EE6352A83FF2A32D5F71E8DCFD05167A9F6DE8BCE131602A83B998A45FC64AD3163D8B4673DEFBE8EA91B0A4E181347D60BCB00DB9DD6A7D1E2553CB7DDCB62586D5D914E5C4DB82CEACB38834F9B2681D81A5D6DCED5304496A84E5137982E6DA1B215701D50A77E22356BAC7734883E19BBD4A619A8730C24C6C45B575B49747CDACE2F081545115C2A4B2AD772BDF51AE4A6F2E7152DD076FB2D8F4C068A08720F4F6230578475FC0A5F0B86FA56D01C7E5D1C310A61D947DF93EC69FD96A5996A3B65F7"
    # x = ML_DSA(ML_DSA_PARAMETER_SET.ML_DSA_44)
    # seed = bytearray.fromhex("AB611F971C44D1B755D289E0FCFEE70F0EB5D9FDFB1BC31CA894A75794235AF8")
    # expected_pk = bytearray.fromhex("D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA18056264432056C416013F5AFE21ADB7F4A5CECA1EE694E580301B47EB634E18C25BC0C964470BEBF10AFDF7587BAE7FC40D45F94519A661A7CD04F7AA0D95AAEE797027D8CBFAEE682ADD859106CCA978F5311A3B53A1699691C1E9E8BF9D2118B23BB1B33C5E9A02F968C800560A865FB826289FB34C936C825D1D0A7DB566B9F30B8E42E7A9AE8F325E51C197CEA36DDB79DF537D1F4102DD44C01B59401770BCCF4D5E8329121863929C91DFCA9C00F862ED7DBF3CF7558F6150B2B05D32F04C1E6E775350248DBFC0AEE58681B5B177CA7BA17ED6C7B4BA7302DC0F349564DB0D83C7F7D1AFE502E27DC465704AA9B7AA50D8F5A14CCC5701FAE3505D3AE11EAD8142AF9EE7991B3B216686126627C60E1769EC805000A6D94076905630D385B7CDA7195B54522A81E8855F3D6DAC03E686CADF72A9142363770283915034ECDF9047F80A8F9594273C7637B514BAF9ACE79A7B5D28F8B0EFD63A1F8B17301F499FD37E448F5E99F118FC7B2A4BFD7DADA350456CE5CC72C5646C57229ECD91082A85EFA259E2AAFF761F0A101A2269C8B88D94F7A8E4F87E7B9F977396E71BCD2B2BF89AB8B829A345D37FE5240CE7216C64EFB01BA8A13700D4BFC9856EACE22FB763BEC7D1E02F0F49B45F587BA6B3F571BE7AEBEA88557492C6C766D7AE298C7902F346DEDA494EEAC39C8767199252C9CE18825385596956F1F41B2BB534F761FA0C89917077B23F8056AA7405F8AE4271B11DF284D4FF50AFCDBFDCBE880131B60E3534091A759531FBE6E14D6057BDB458449AE4BCEC26580877331359E794E9D75BF454122264CCD13F9349C8250F0BB586B5BB482EB74524FD12F0F61EDD28411D072FCEC556BBC5569AFCEF1A62C26078088A77ADA5976E6A2A99E98C898E5789DE786B45708271957D88594DB7FBABE23DDBF1ABB12E715BD576483EAD259BA6553E95AE65AEDB55751532B98F32376BADDD2532E5801A255FA6DFC3FCCD5FC5110EE231450DDA25C4E09B89B577B8589C7179B06D62ABA652BD6DAD5159E8D7B84A5879F075EBD31ECCE03D2F1E508FB229665B4232B905638176AFCF232D4C19AF38A812C8D2AF2776CD444E94D46816EE68E7B5CD5AC1622518682EEE88E0F64358181EF35A8EC71E00E70F1222F494615A4FDF7C769CADB0E13B2F15B5EDA38809A5960D25090C1513636DE242BBD9A79F77CB45C81557D6F1D18991B37BECD4CAD9707B1F88920B69A55CD52CDAC2318287D4B13BC9CBA6884F9A38054493BDF91B29C2B7A71E2DD8ECFCDD0259BFFF402251CA2C95042AF917EBB669ACE5B354DC393A10F66847D546C47EDA695AD3A985834292E68A024AB6045ADF36DD2A58993A292B24837F61711CB59EA8DEB103F63F971E385CE0490A0709C890CAF57ED86991ACA729DBEFEB023D4356B7144485B7AF45559C3FF722EC8FCD8BEFBAF41119A24C9B686A79C38356F3FC55720F03AC89B3187CECC0C1247B9F8DDD82B8B415BAA6BC7A25E2529C41CC9765C768DC6A555D6114707879E810BC4C7472A07E8B90B0F41B8B4CABD5326B190572B664127E2FB476D88DB32D42D50BCD7F637AB2B7D13E0A7D03DFA30B0B81F7D2917C1CA5260BF71230F7342A5BB9F9261D966CDEE85F768A9B8B509F094C60E0C08BAC278827E84E6590141FF8C10E9B51FBF6E7724030EEB8B59731E47FA3D130407F833455386B66CBC453FF4BACC0467D747A1037EA57B3DE4421C3050DC6D33268CABE633C6E54C13D64973751798A99D8C53A2132E5BBBF8B2961B9E800F01940C700E47E4E1")
    # expected_sk = bytearray.fromhex("D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA180565499F298E78451161F0E9FF4B862815F3D5D33393AF3E677EE2460DF7BF3AE6E9A80F12A9B349DFDB9B3D0513BFFE620394A80A2883BCC69F1847057AC3BF35E63A72E60D5267D606C524AB847BCBC1113874755248DFBE583A2F0DB0FCBC8CD9C9008128028CA962CA038680919464C008ACC084D00466093002A541631D9A890D21200DCA8515418655C2005C8306A0C01204B040E1C913001418C11448C1A3206CC060C50B27058244593A0119822012426260B402603090E5A12020301611A14010119625222200CA3650B09904AB44D80264D5A366263906D1207320339491036111223041888202421880AC82819806C492629C4922062188993367204220282086558945018B32823335263A20112498C91B428E4C645DB82694B021101270A09397220314042A44DD23092913444C134091946200C210D4B36101026111437699440895308204324019B464152B8854286891B11880C41449C3252D2200520320C13948510930582C6480211865B262CCC884444B42DD2088E601062CCA66D8344451B3765C8B05180066922040CA40489514424A3404162965019C78160320D9816921220101915016248051C362E59308A13126AA3444610A52900C98C93C4100BA04508170558486201086C183392DCB86DCCB08D59906420026014B309104945A3A60012472E1C005203C91003492C1C92811B396613465001294650208462106900255043B8201CC68D981284A03204220821DBC46CA10622A09071E4204D213984D4B44023432401B6001A318289188209067112B131C3B624CA126C90066201036C0825909B3669E28044982428C4B0100B384159986D4B220118382618332E11150C49A8088C48898BC62862864C00461224A681C3C681E0C60D19046E9C9441C1283203466E1321251CB5854AA084A424319CB02048946014B7404814501319691AB00012B12413C880628410C31061D94040DB4806898869119289149700C204241CB7058422284B3646130132CB406160140CE0005218010A50228118278013329004269110A32C99B42C5C44464B3632DC468A49B04858884961C44102A2650302624326410B9885A11426481092DA962898C8006028104386688342254412102343511C326A09884511C5654010065BA001CC32889922258A1666420611898241120165C3140621446C09450149424C99948C0045022C7B04EF5AD7D8FD0179FC8AFDA5DCADA47CF7926345F6CD5F072625345A613C92D8D1EA7CFD213DFCD7896567194767DA47E3B3BED4E3F2CF727C78F7FD63855CC68EFEA538728CB803830B6FC646A865B93A46CB4EE30968C8A61D913DACC0483CC19DD790ACEC8E07BA8F5E924D7F024B69552ECEB588A94DC2BF11BE97A59A8065043525C628B59CE423CCF8293C78363C98662EE883F8B46A243AB2AB8ED3EB24C4AFDF383B2E9F0F969D4E6DE19B06BF6837ABDF751725B97D45389138EDB253A78C78DE841224FD7CFFAE2D8D58FF5D9B9ECD9C209F77CCA5D167B1A93EC5A9B891E1E4DBF1741DA1C4AAE7622B15F040DA03350CECF2649E309D38A8D5F8AA218900F321557C593DCB83A6A5A2C3C13129A07236E6F50864E4E9E11B840F3D6E6B74ACFE7394DAD62167E1CAE165B9207596B1C7CD3DE62558C24723C8F74BB4203F0F5272D0E1E8EC631BEC8ED97E9DC58FC843A901329D566A3A230D138B3AAC9B29CCDBEFDD2A6AAA7AC2C57A4850AB0AE2425D5A1F572848755D8894222F37885C8D7D34C02FA95457C7EBCF1D56B3361DAAF75F43399CA1958609BF9654A0E50C6AC0B405014AB252767A8C31F9D23BF9DAE2FC6A2548215B9E77F2FD28D049232763109367B1AB9A25DBAE50ABDA2422A8F262A5A19D4035FDA91433072E5E1DC927425EA3D1DE222230889373EF0D08E475662B6BEBDF6C4E48AE442331D9C7FCBCA2C41901543AEFECB866D132090AA366A358939EF9AFA92B533A60444C95BB50EC36DC0478F4511948E34A4A2EE53B439EECA84B53B3470E86413C04822CB6209FFB97C777DA0BE08F46F629DD64BE853901BCF32D1BB5EFC5512B0AC678154E98E862A9DF088243A1E279C55253AA3666AB343909B2421917FAF7FB4AB09A0268D3BE0CC9DEA933375975EC7E3AC22E50CEB3BE9FB3549EDF77D129FE75B1D24C2BECDBCD734F6A03349A4EBE17323985A9FFE33C1F68E99F321B3EB918C0BDE1A53A79906BD5704351693AAF92804310DF2A4F05E1EAAFC241C308ECE274B9B09935D5889EA1F58F580D2CADD2F9F9712279F0FA1F8AE4AEA4D993C55CE420DDFE5527FD0ABCEE4FC8F547F6C335BF6BD6827CCA513567CF4744CAAC1C373B8F8E12E2234B0341F7F3974BD9A2079EB5C48F25CF6400A1299E42F2D77804433E182F8EE02A1966846152FDAA949B9979260D1B511FAA2A705A2282E3955B6B906A2FAA28FD054A9B78E424FA5895650E60A2B1BEB1AA6480EBCC0A01657A8344AB896DFA7C023DEDA05EF642134A3AB9A783DA9AE6D189D2E2C2574ED909D757230885C0155644F25166A0474F618FBB5066446C7091D6E6E7EFAA6890D3704F8FF5170F2E2F656FC7825C2F1175A8DE14EC4CDC9F7D4D0996199D63C44E53D8ADB961335C954462B19B9BF52A67E3DE2BE220156E4DC9445904FA9CF42C2DE922231FF1BE379830ABF6F00B46A79F470E2A4471730CB8C29A000EBEBE10A2789A714F07F432962827AF53B321B8F7DE08A95D47FFC223DF9A44EE0FED3D5BCCCD948420E4E8D452AF900D49C022A3FB6C0D6887C836393597E40D36613E77CCD8A306A21CF826D20D9F823513815D885EB74F04ADEDA4051BD0998F7C9A48015BF662D72F6A99AED192C283D936E65F48E9748ECF2E0325518EF4F4B6991BC3956F3954535218B3727A721E31DAE286AB9947F13CD59E8F0FE7214DFB1540731049216D8069DF7A2BE167623684D142F721444204DDBAA851629A43DD9F75554ECAC9BC397C497B9097F85403DB3F6DD8AE83E4B0DE698F5E0AEF23FBCC21167E10EF554791F87DC9BD58F8EE82AF76B0846510873159A534E129DAF7B567BC17D5EE78C9630EA506DBEDBA84E2D1FC5DF9154903038A0FE8EF6C3AF6028D71CB2CF593596316A989A28DB6CF1814999DE9F597ABD1ABC20A168E2F2FC12F5C3D04D3581E0DF9CC2F890C207F97861790E0D1CDC67590DEEC5C6E9BA3EC2FB2AA3F0F047FE210CBE8EB03CC5F976A74DF9EC1086CD4D1A9B8E47888BD77095C305852E02C85F5B9BCDD6FF1C2B79E299EE6352A83FF2A32D5F71E8DCFD05167A9F6DE8BCE131602A83B998A45FC64AD3163D8B4673DEFBE8EA91B0A4E181347D60BCB00DB9DD6A7D1E2553CB7DDCB62586D5D914E5C4DB82CEACB38834F9B2681D81A5D6DCED5304496A84E5137982E6DA1B215701D50A77E22356BAC7734883E19BBD4A619A8730C24C6C45B575B49747CDACE2F081545115C2A4B2AD772BDF51AE4A6F2E7152DD076FB2D8F4C068A08720F4F6230578475FC0A5F0B86FA56D01C7E5D1C310A61D947DF93EC69FD96A5996A3B65F7")
    # pk, sk = x.KeyGen_internal(seed)
    # print(pk == expected_pk)
    # print(sk == expected_sk)

    # "tcId": 5,
    # "deferred": false,
    # "seed": "885B7DF7CF6695F30AA3F1BC6A3840B8CA3101734118AE619166838AA3EFDBCD",
    # "pk": "E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885BFE5E31A1E0339BF83F848092B623761C8DEADA4B6139EA700A1A91E5164B99357FAD504B095A74AD684E4DE51471D0976ED23E6D8164F7469E50478A91D45EA9CAF0DEA00A618FD60756AB09E617293DB9859C82EDDFF4E5274AF10019A233309073ED469F8E438CCD82894F6D1F095C2A40F05BBA63B58984458A202016849FA2A963FF6B7EB55C3D881AAA46399E76E2ECB8ED8F05F15DC60694690B1E7687608D5B97684F2EF59A24625C4FFA0EA6C3CF410C275E37B6FD936C29A803F3F1E90EA53B7516785AAC68C7AB89EF15562AEC97E258B30D7B3947E655228A5073232142FB96D4CD64C562C2D0803D109DB76A2828E0A90CF87EA097E3791105008B015E236FBBB1E45A19C8A46132EE13B651B81702C2D19A41FB3FEEE728BC5E67DCEB3236EE5689E9EDDC9201EA91670459596A35DE88552A3D18F47F24CA86717B77702808398238D59642A38FA10F6D17BF28DE18184075E6C4CE4B50AE2AE0D59D080694E13FD6500F96AB34B4E2882755A11ABB9F4F56A275F43329A6CDC6FEA7220F63D6060AA389E5328B4DE152A17575369A62EC41CAE80F4F7FE22EE78225485DE16AF283024604D979FBE7567C8A6184AE0C967BA5A8D8245E8CF9623B36574AA27E0E3F8F2F5D8A1466D4C45D17DF60FFC6CFCD9C7B029763C3139087D7AE8B61F0BF34A1E03261B44106A5A18C8655AD7740B335564B2C2DDAA81A52307D0ED0DD777D955C90DB55682F7A5563D68DCE388A41E65503FA2B5FCA33F636062DC97BF3CDD9201DC1B973A4EAE1B7A45A72573DCAB1029E221E9EFA2863440C4A41B5BB23FD457CC5847E80628B8D6F5E713789DF20350B7BB295344843023D06C793BA30F9C4552BC7579E484119472F3153D2621C948DDB9701A205E9B56ACBF08684CA237AFAB9DC9894B885B24AABB86BC22B8AFA248DFB776EEBACEE5719E93E8455132EE28B6C9F716BAE0B91F22C14A658AC1CC6D15BBFE1184890D5B0573CA167BF3F3531637F0BE6700E5D8B279650CCE11D5246097BCA3B43722396708CD0A4970DB56263FB8C04934AB7EDB97613276DD5ECC5555F45C1BF0405E83655D09A79E179C877B7B53750B2D6862A6D96B2E3112A81D52BD3A96D233E6B9825CC48205B344B3844D1B10469C4472D2545F9594EEF1340400A9634848DC5714F21BBA6B3D12DF8596032CE265954890B71239CCDD141872B4652F32B861A5E01B2E441D2D7765E489E202F79D6DABB09C082FBEF56A3D32AC30DD76434BE495AE13FCAB1E9CD16CBD5FD3E9CC50C25503C5141068966DB483DCFF107A0505AA3DDE60C66FF638C7F84BFF86F3BC5C2F8DAFF19BC8ED84A2DF6F39C04E61F77B0FDF1D9ABF204795AD545D80E7524508F221C9B80B244A396AA46FF0DCE813E704BD9C402A5317253E481A8742AE6B99A5D7F5BFC0D5A266B3EE57A84588F7E825419FAD1D30BF7F856585BB6CB22E7639CB6F02DD52CCCF9502CF30F4C9FB7A54291058F81FAA4B1525C9AA6C5DC798263C07922C428E43027EB4F4DB3E41120DED9A74CF1324B5E9A4612676134E650C22300DC078DD5B84611BF105703EDB7D64AD68AF62EFA52D8CD684DD93599ADF15EB2A0A51EDC60633741AD1C9CBC15C092C2717C619D01FC6E2483B6831DD8672B97FC0CC7E86FE8689D30C02D2B710AECEC599E0C706B7284E13174B1C1D4C4F5F88335157DD837A823488D0E1219A2D92F9EBFE7B4347C687A4DA3EA6026F96712632CF9ABE869812F6F12F5200C22C5F52E12E1A08DEC556ACAD92AE79FDB4073146D133C000E",
    # "sk": "E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885B04EC298F3AA93654E01A33009C14A0E4185CBD4245CE8B5A2685DF7E24976D3A709BF64D5BAAA1791D413F8DA075A552705C11CBA7404420C31A291FAC5824C9176539015C3F03AD5E63646A93314EA25909ACF0C95F7015DC8446D063FAC8D6199650191125CB848122C83104A3092434615B442E48922452000019C160222484122700CC322D02C9408994292109428A42494A0262100252C01801081040A0C6908242001C2530C2340963986C14C90C18294A0A870104A99082A04548108889167093322A98288DD1A42801286142486219A8441BA5248120302222080A139109B2240226410B2888A228919C0892DC420C9802051AA92C04B35151168E18C044C4C66041808844B04DE488280042868188409142461C812C12286510250E18A60921220A14C44918B18401C70C80A684A2A06024468E18C12D82902C89B68914198E80148511C790D2C82918093009A170D1948C929061A0026C5426508A26821B494C92022D89305002886990184CD498491949268020889B40110C3584A2B26D9280450112485A288D82480C9A02898A846CDBB87022272521B5841216421B840DDAA64063146DC4C69184C8299236020A220D032445081385903409028089C8880022238A5A8050D310854A124EC9B46103122D8BA44DCC149160128840B6201CB9015904040433890B0802C18209A1468AA13289C8A611E0143199B00981462100B9611396441A982023258A4312489C36680C0670E43626E11290D8B64591B22918136A049501241942249471201628404662432848441801C12848A42092420425DC8449DB124E0A468C03274420322D0CB06C0B81110AA70C1B83710A312221497061A4609C3222238664D2C28D0C92259A94315A442222088E8A3690C8186859364C08438810226D22144C8122840B22520A2620A28048DC128091904DC1381252848413B771E382909A2602E4B0714B186022A5889AB6514CC80161C200CB465284C801C82865D230268B100620310DDA184AD0A208A23891C8028141162958B068432671C224658CA2614280290AC24920401042C68002444164846018A76020021013924814272D8B160A13C510D9347080A00DD9380843968192A24019B16D40423184A031D2442020988892947098064A0CB94592422C840084DB202213928000A38D94986812140694326914488194168289A46412A760B8AA3D5DEC680E7B2D97ED475A39EEABED483B48BA9B453A7D9D8AE851EF1F82FA57BD3F05D03180B744766F3132D868F1E61BB3529523F85C90E7071137BCC54FF472B378E664A0117451CE47F7234575082E8B66941DB645D27ACA53DF4056C6A79D41D8EFC3A27C676E83C43019CB56C8676FFABE1F924456FB102C2A1059113A1D049CE6063A56D7B0EA8EEC76674CB36152C599D78B6B9ADBD11FCA00F0B3E2165C6130029913ADDBDB64E5CFFCAA65EDDC272205949A0FC601ED6B31CBC710CD4881E4F51D3489BD97342FA8CCACF9B03F07D952C37217C057EFD8348534D0834B6537D14B1898D5C6644D20285A4269FB7D20585019ACAC0634C9A7A0BC91E595637F9B16DC454F38A1CB39A66E9D8BBA5C496644D0584CA0ED14A03F4B03901C82D6CCFC5151C84103EEBC22F2D190766C60C31F3F80AECF8E3CAF750E02D2745F4224C4F4390BE9BA43DA82B5B3270BCFC448AECAFC87EB2065C0D4C169609B78B3C4531BE26A84A4957A5E40037C4BA223EA5F19837AC3078CC5219770445A57A23B2255751A654A84A95983BFE09290A058646184A4019A678E0CFCC3169EF5CE169956A27CD987172EFA8F635B81BCA50C1F12577E126D7AC0FBCB0356220DA0BD2F3EBB2C0474CAB6CCE48D9FF58743ECA8BF0E3C6A85D045EDD4426CC33F86093BB76D946E36779D7E8C6D451027A826E8A8C2A1DC6EC5658DF8804C25F17D7C5BB4B8598D495A8E198BC43AA9B75D85F5ABE22D95788A59ECE32F4EEE60D30980CBEE238B314D520918E0FC73BAB0B8242EBF523B9CBFB606A68D7F8884DA73979BF826507F7A348266925C8D1168272F7851D5610034E97DACD3B014E0AC6A04873D1D1700E76231CDEB7E8ABC18EF36ED950744BDF888F958FD7A3955AEFF2016EC2D6C1896CCB4A6FB558F07FF180D786925EE1E818BED17889F7D3B0CEEA8D5CE41F477C4B6B4BBC17D1251A0E4FCD8F42AB3F0B95A2E060C688A6B912E4B7438C4CD144FA4DD2B3D7E6212497CCCD111033523BBC907EB29C7674A80D0BA4C27E24CE74998475A64C0FD82A45B3BFDF70971CEF736B1BB457F30D918337D7EA5845B97C1E3232440DC9C82140E63CF88EEEC3EA4B5BCCC898EF909A556FCE59D1D4FD6893D3F075DBC37F1D25E54A5FAD6B647D2EAFBA16CC4C47E253EBC0885E5587BCBDBA3770082864899654722F29058B8BD14C739463B340962556E9FAB20F1B81FC799D083BD2839C9FB220FD28F0319F64512EAE81DEC1952CB9A74976F42E67B72533E68651D1D4437DCECD21840318E4BA3989A965C8671BBB2594F32797EFA3EC720CEA86B456361819E9DC13C54381A03339F35856D31785CA4B863C0E896ACED0016FB4F0C7ABD5C6BBD0ECC8BE62A87589DF02B6AAF03ACADCE4B7B72B9F60B9B1AA662B96A13E10C2BAE862F9630C9CFE1FEA119BAE1AAF0C7DF95FC08933923ADDBC483D134C60BA303FCEB4096A389A333381DD8355FD3F39F9D9D6A79DEE51282A153E55E5823759F4B2258E7CC0DCF0D41B40F76E3435A68DD7E92A27BCE126EAAADD224A049FE4F920BBCAFE1A057B29E9B9E64E64455BA54140BB4F0E4D4D20507C493E17AE36C6B6A36DD3853894FFB44729721714ABB859908D84982071137BF5B359E3019A7A267DDB333D506DB8A918C2522F267B5F4700A9179C7C0668CFB0BE412EA7F4B36C74A1761C50E15C5D292B59E9C1E90BFAFADC8C05D7146FDC9DF78777E886A0402423072381FEE790F5A0A5F6B64F3BEBE02CCC98EC0205D30A471EF69CFC22CFC1C529FFC3959D2C57CA744170F3E95EF0A9166C67A4BB41BA66A9D46556EBDD2E8C6044EADB0BD49E298D806456062CFDE32C017D881629381BB0B93C14F70FCB9A48E7714B9DE2E3F636BFD1167E1E3476928882B333968AF9F3953FE40C51DF6EEDFE056CF71A962D936A821FBFB9191D60096C27CFD8F92BB64BA4D7B47EC12DFE0BDE1CE9E25BA50B33622BF347CF09C607A60C9AE80646B6958B8A5873551B4F927653ED379349D3382D856602722DBED05DCD0999CB88A20E04006B3E302E165B5AA421E1C4226C19EE0C75F7F6CD46DE0F243F3367886CE804E57CE16A3DB51304DC2492649CFF16731FC748516020C7B2AC3134B75EBD685088D177B7BFE1EBA595C798619476B8B2F626D3837A0397A777A84AAAB4E998CE5D1174399BCFE5C5241E5288A241C4B34036F8B30C0862DFBA419AC96DE6F4A0A5E3EEDB0532BAA2DEFECE28B912D6F50707F5CF743DDE5BD33D98E9108FAD9E83812F0BB143FB0F82CEE14DB90531AE1738978BB69C30E7488FDA9232E6BAF117FA45601E300"
    x = ML_DSA(ML_DSA_PARAMETER_SET.ML_DSA_44)
    seed = bytearray.fromhex("885B7DF7CF6695F30AA3F1BC6A3840B8CA3101734118AE619166838AA3EFDBCD")
    expected_pk = bytearray.fromhex("E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885BFE5E31A1E0339BF83F848092B623761C8DEADA4B6139EA700A1A91E5164B99357FAD504B095A74AD684E4DE51471D0976ED23E6D8164F7469E50478A91D45EA9CAF0DEA00A618FD60756AB09E617293DB9859C82EDDFF4E5274AF10019A233309073ED469F8E438CCD82894F6D1F095C2A40F05BBA63B58984458A202016849FA2A963FF6B7EB55C3D881AAA46399E76E2ECB8ED8F05F15DC60694690B1E7687608D5B97684F2EF59A24625C4FFA0EA6C3CF410C275E37B6FD936C29A803F3F1E90EA53B7516785AAC68C7AB89EF15562AEC97E258B30D7B3947E655228A5073232142FB96D4CD64C562C2D0803D109DB76A2828E0A90CF87EA097E3791105008B015E236FBBB1E45A19C8A46132EE13B651B81702C2D19A41FB3FEEE728BC5E67DCEB3236EE5689E9EDDC9201EA91670459596A35DE88552A3D18F47F24CA86717B77702808398238D59642A38FA10F6D17BF28DE18184075E6C4CE4B50AE2AE0D59D080694E13FD6500F96AB34B4E2882755A11ABB9F4F56A275F43329A6CDC6FEA7220F63D6060AA389E5328B4DE152A17575369A62EC41CAE80F4F7FE22EE78225485DE16AF283024604D979FBE7567C8A6184AE0C967BA5A8D8245E8CF9623B36574AA27E0E3F8F2F5D8A1466D4C45D17DF60FFC6CFCD9C7B029763C3139087D7AE8B61F0BF34A1E03261B44106A5A18C8655AD7740B335564B2C2DDAA81A52307D0ED0DD777D955C90DB55682F7A5563D68DCE388A41E65503FA2B5FCA33F636062DC97BF3CDD9201DC1B973A4EAE1B7A45A72573DCAB1029E221E9EFA2863440C4A41B5BB23FD457CC5847E80628B8D6F5E713789DF20350B7BB295344843023D06C793BA30F9C4552BC7579E484119472F3153D2621C948DDB9701A205E9B56ACBF08684CA237AFAB9DC9894B885B24AABB86BC22B8AFA248DFB776EEBACEE5719E93E8455132EE28B6C9F716BAE0B91F22C14A658AC1CC6D15BBFE1184890D5B0573CA167BF3F3531637F0BE6700E5D8B279650CCE11D5246097BCA3B43722396708CD0A4970DB56263FB8C04934AB7EDB97613276DD5ECC5555F45C1BF0405E83655D09A79E179C877B7B53750B2D6862A6D96B2E3112A81D52BD3A96D233E6B9825CC48205B344B3844D1B10469C4472D2545F9594EEF1340400A9634848DC5714F21BBA6B3D12DF8596032CE265954890B71239CCDD141872B4652F32B861A5E01B2E441D2D7765E489E202F79D6DABB09C082FBEF56A3D32AC30DD76434BE495AE13FCAB1E9CD16CBD5FD3E9CC50C25503C5141068966DB483DCFF107A0505AA3DDE60C66FF638C7F84BFF86F3BC5C2F8DAFF19BC8ED84A2DF6F39C04E61F77B0FDF1D9ABF204795AD545D80E7524508F221C9B80B244A396AA46FF0DCE813E704BD9C402A5317253E481A8742AE6B99A5D7F5BFC0D5A266B3EE57A84588F7E825419FAD1D30BF7F856585BB6CB22E7639CB6F02DD52CCCF9502CF30F4C9FB7A54291058F81FAA4B1525C9AA6C5DC798263C07922C428E43027EB4F4DB3E41120DED9A74CF1324B5E9A4612676134E650C22300DC078DD5B84611BF105703EDB7D64AD68AF62EFA52D8CD684DD93599ADF15EB2A0A51EDC60633741AD1C9CBC15C092C2717C619D01FC6E2483B6831DD8672B97FC0CC7E86FE8689D30C02D2B710AECEC599E0C706B7284E13174B1C1D4C4F5F88335157DD837A823488D0E1219A2D92F9EBFE7B4347C687A4DA3EA6026F96712632CF9ABE869812F6F12F5200C22C5F52E12E1A08DEC556ACAD92AE79FDB4073146D133C000E")
    expected_sk = bytearray.fromhex("E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885B04EC298F3AA93654E01A33009C14A0E4185CBD4245CE8B5A2685DF7E24976D3A709BF64D5BAAA1791D413F8DA075A552705C11CBA7404420C31A291FAC5824C9176539015C3F03AD5E63646A93314EA25909ACF0C95F7015DC8446D063FAC8D6199650191125CB848122C83104A3092434615B442E48922452000019C160222484122700CC322D02C9408994292109428A42494A0262100252C01801081040A0C6908242001C2530C2340963986C14C90C18294A0A870104A99082A04548108889167093322A98288DD1A42801286142486219A8441BA5248120302222080A139109B2240226410B2888A228919C0892DC420C9802051AA92C04B35151168E18C044C4C66041808844B04DE488280042868188409142461C812C12286510250E18A60921220A14C44918B18401C70C80A684A2A06024468E18C12D82902C89B68914198E80148511C790D2C82918093009A170D1948C929061A0026C5426508A26821B494C92022D89305002886990184CD498491949268020889B40110C3584A2B26D9280450112485A288D82480C9A02898A846CDBB87022272521B5841216421B840DDAA64063146DC4C69184C8299236020A220D032445081385903409028089C8880022238A5A8050D310854A124EC9B46103122D8BA44DCC149160128840B6201CB9015904040433890B0802C18209A1468AA13289C8A611E0143199B00981462100B9611396441A982023258A4312489C36680C0670E43626E11290D8B64591B22918136A049501241942249471201628404662432848441801C12848A42092420425DC8449DB124E0A468C03274420322D0CB06C0B81110AA70C1B83710A312221497061A4609C3222238664D2C28D0C92259A94315A442222088E8A3690C8186859364C08438810226D22144C8122840B22520A2620A28048DC128091904DC1381252848413B771E382909A2602E4B0714B186022A5889AB6514CC80161C200CB465284C801C82865D230268B100620310DDA184AD0A208A23891C8028141162958B068432671C224658CA2614280290AC24920401042C68002444164846018A76020021013924814272D8B160A13C510D9347080A00DD9380843968192A24019B16D40423184A031D2442020988892947098064A0CB94592422C840084DB202213928000A38D94986812140694326914488194168289A46412A760B8AA3D5DEC680E7B2D97ED475A39EEABED483B48BA9B453A7D9D8AE851EF1F82FA57BD3F05D03180B744766F3132D868F1E61BB3529523F85C90E7071137BCC54FF472B378E664A0117451CE47F7234575082E8B66941DB645D27ACA53DF4056C6A79D41D8EFC3A27C676E83C43019CB56C8676FFABE1F924456FB102C2A1059113A1D049CE6063A56D7B0EA8EEC76674CB36152C599D78B6B9ADBD11FCA00F0B3E2165C6130029913ADDBDB64E5CFFCAA65EDDC272205949A0FC601ED6B31CBC710CD4881E4F51D3489BD97342FA8CCACF9B03F07D952C37217C057EFD8348534D0834B6537D14B1898D5C6644D20285A4269FB7D20585019ACAC0634C9A7A0BC91E595637F9B16DC454F38A1CB39A66E9D8BBA5C496644D0584CA0ED14A03F4B03901C82D6CCFC5151C84103EEBC22F2D190766C60C31F3F80AECF8E3CAF750E02D2745F4224C4F4390BE9BA43DA82B5B3270BCFC448AECAFC87EB2065C0D4C169609B78B3C4531BE26A84A4957A5E40037C4BA223EA5F19837AC3078CC5219770445A57A23B2255751A654A84A95983BFE09290A058646184A4019A678E0CFCC3169EF5CE169956A27CD987172EFA8F635B81BCA50C1F12577E126D7AC0FBCB0356220DA0BD2F3EBB2C0474CAB6CCE48D9FF58743ECA8BF0E3C6A85D045EDD4426CC33F86093BB76D946E36779D7E8C6D451027A826E8A8C2A1DC6EC5658DF8804C25F17D7C5BB4B8598D495A8E198BC43AA9B75D85F5ABE22D95788A59ECE32F4EEE60D30980CBEE238B314D520918E0FC73BAB0B8242EBF523B9CBFB606A68D7F8884DA73979BF826507F7A348266925C8D1168272F7851D5610034E97DACD3B014E0AC6A04873D1D1700E76231CDEB7E8ABC18EF36ED950744BDF888F958FD7A3955AEFF2016EC2D6C1896CCB4A6FB558F07FF180D786925EE1E818BED17889F7D3B0CEEA8D5CE41F477C4B6B4BBC17D1251A0E4FCD8F42AB3F0B95A2E060C688A6B912E4B7438C4CD144FA4DD2B3D7E6212497CCCD111033523BBC907EB29C7674A80D0BA4C27E24CE74998475A64C0FD82A45B3BFDF70971CEF736B1BB457F30D918337D7EA5845B97C1E3232440DC9C82140E63CF88EEEC3EA4B5BCCC898EF909A556FCE59D1D4FD6893D3F075DBC37F1D25E54A5FAD6B647D2EAFBA16CC4C47E253EBC0885E5587BCBDBA3770082864899654722F29058B8BD14C739463B340962556E9FAB20F1B81FC799D083BD2839C9FB220FD28F0319F64512EAE81DEC1952CB9A74976F42E67B72533E68651D1D4437DCECD21840318E4BA3989A965C8671BBB2594F32797EFA3EC720CEA86B456361819E9DC13C54381A03339F35856D31785CA4B863C0E896ACED0016FB4F0C7ABD5C6BBD0ECC8BE62A87589DF02B6AAF03ACADCE4B7B72B9F60B9B1AA662B96A13E10C2BAE862F9630C9CFE1FEA119BAE1AAF0C7DF95FC08933923ADDBC483D134C60BA303FCEB4096A389A333381DD8355FD3F39F9D9D6A79DEE51282A153E55E5823759F4B2258E7CC0DCF0D41B40F76E3435A68DD7E92A27BCE126EAAADD224A049FE4F920BBCAFE1A057B29E9B9E64E64455BA54140BB4F0E4D4D20507C493E17AE36C6B6A36DD3853894FFB44729721714ABB859908D84982071137BF5B359E3019A7A267DDB333D506DB8A918C2522F267B5F4700A9179C7C0668CFB0BE412EA7F4B36C74A1761C50E15C5D292B59E9C1E90BFAFADC8C05D7146FDC9DF78777E886A0402423072381FEE790F5A0A5F6B64F3BEBE02CCC98EC0205D30A471EF69CFC22CFC1C529FFC3959D2C57CA744170F3E95EF0A9166C67A4BB41BA66A9D46556EBDD2E8C6044EADB0BD49E298D806456062CFDE32C017D881629381BB0B93C14F70FCB9A48E7714B9DE2E3F636BFD1167E1E3476928882B333968AF9F3953FE40C51DF6EEDFE056CF71A962D936A821FBFB9191D60096C27CFD8F92BB64BA4D7B47EC12DFE0BDE1CE9E25BA50B33622BF347CF09C607A60C9AE80646B6958B8A5873551B4F927653ED379349D3382D856602722DBED05DCD0999CB88A20E04006B3E302E165B5AA421E1C4226C19EE0C75F7F6CD46DE0F243F3367886CE804E57CE16A3DB51304DC2492649CFF16731FC748516020C7B2AC3134B75EBD685088D177B7BFE1EBA595C798619476B8B2F626D3837A0397A777A84AAAB4E998CE5D1174399BCFE5C5241E5288A241C4B34036F8B30C0862DFBA419AC96DE6F4A0A5E3EEDB0532BAA2DEFECE28B912D6F50707F5CF743DDE5BD33D98E9108FAD9E83812F0BB143FB0F82CEE14DB90531AE1738978BB69C30E7488FDA9232E6BAF117FA45601E300")
    pk, sk = x.KeyGen_internal(seed)
    print(pk == expected_pk)
    if (pk != expected_pk):
        PrintPKs(pk, expected_pk, x.q, x.d, x.k)
    print(sk == expected_sk)
    print()
    print(sk.hex())
    print()
    print(expected_sk.hex())
    print()
        
