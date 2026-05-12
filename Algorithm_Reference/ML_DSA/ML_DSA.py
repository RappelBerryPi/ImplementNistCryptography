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
        return self.SignGivenRandom(sk, M, ctx, rnd)


    def SignGivenRandom(self, sk: bytearray, M: bytearray, ctx: bytearray, rnd: bytearray):
        #10
        temp = bytearray()
        temp.extend(IntegerToBytes(0,1))
        temp.extend(IntegerToBytes(len(ctx),1))
        temp.extend(ctx)

        M_prime = self.BytesToBits(temp)

        M_prime.extend(self.BytesToBits(M))

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
                w.append(self.Inverse_NTT(temp[i]))

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
            if (self.InfinityNormVector(z) >= (self.gamma_1 - self.beta) or self.InfinityNormVector(r_0) >= (self.gamma_2 - self.beta)):
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

                temp_2 = array("i", [self.q] * 256)
                ct_0_neg = list()
                for i in range(0, len(ct_0)):
                    ct_0_neg.append(self.SubtractNTT(temp_2, ct_0[i]))
                h = self.MakeHintVector(ct_0_neg, temp)

                sum1s = 0
                print(h)
                for i in range(0, len(h)):
                    for j in range(0, len(h[i])):
                        sum1s = sum1s + h[i][j]

                if (self.InfinityNormVector(ct_0) >= self.gamma_2 or sum1s > self.omega):
                    z = None
                    h = None
            k = k + self.l

        z_temp = self.ModPlusMinusVector(z, self.q)
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
            j = j[0]
            while j > i:
                ctx, j = H.squeeze(ctx, 1)
                j = j[0]
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
    def Power2Round(self, r: int, dpow2: int):
        r_temp = r % self.q
        r_0 = self.ModPlusMinus(r_temp, dpow2)
        r_1 = (r_temp - r_0) >> self.d
        return r_1, r_0
    
    # algorithm 35 ancillary
    def Power2RoundPoly(self, r: array[int], dpow2: int):
        r_prime_1 = array("i")
        r_prime_0 = array("i")
        for i in range(0, 256):
            r_1, r_0 = self.Power2Round(r[i], dpow2)
            r_prime_1.append(r_1)
            r_prime_0.append(r_0)
        return r_prime_1, r_prime_0
    
    # algorithm 35 ancillary 2
    def Power2RoundVector(self, r: list[array[int]]):
        r_1 = list()
        r_0 = list()
        dpow2 = 2**self.d
        for i in range(0, len(r)):
            r_1_temp, r_0_temp = self.Power2RoundPoly(r[i], dpow2)
            r_1.append(r_1_temp)
            r_0.append(r_0_temp)
        return r_1, r_0

    # algorithm 36
    # See power round 2 for the definition of mod+-
    def Decompose(self, r: int):
        r_1 = r % self.q
        r_0 = self.ModPlusMinus(r_1, 2 * self.gamma_2)
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
            c_hat[i] = c_hat[i] - b_hat[i]
        return c_hat

    # no definition 3
    def InfinityNorm(self, w: int):
        return abs(w)
    
    def InfinityNormModQ(self, w: int):
        w = self.ModPlusMinus(w, self.q) # q is odd
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
    def ModPlusMinus(self, z: int, m: int):
        # return (z % m) - m_2
        temp = z % m
        if (temp <= m // 2):
            return temp
        return temp - m
    
    def ModPlusMinusPoly(self, z: array[int], m: int):
        returnArray = array("i")
        for i in range(0, len(z)):
            returnArray.append(self.ModPlusMinus(z[i], m))
        return returnArray
    
    def ModPlusMinusVector(self, z: list[array[int]], m: int):
        returnList = list()
        for i in range(0, len(z)):
            returnList.append(self.ModPlusMinusPoly(z[i], m))
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
        print()

def printSKs(sk: bytearray, expected_sk: bytearray, q: int, d: int, k: int, l: int):
    rho = sk[0:32]
    K = sk[32:64]
    tr = sk[64:128]

    rho_expected = expected_sk[0:32]
    K_expected   = expected_sk[32:64]
    tr_expected  = expected_sk[64:128]


    print(f"rho matches: {rho == rho_expected}")
    print(f"length matches: {len(sk) == len(expected_sk)}")
    print(f"K matches: {K == K_expected}")
    print(f"tr matches: {tr == tr_expected}")

    part_length = 384
    start = 128
    end = start + part_length
    real_s_1 = sk[start:end]
    expected_s_1 = sk[start:end]

    start = end
    end = end + part_length
    real_s_2 = sk[start:end]
    expected_s_2 = sk[start:end]

    start = end
    real_t_0 = sk[start:]
    expected_t_0 = sk[start:]

    print(f"s1 matches: {real_s_1 == expected_s_1}")
    print(f"s2 matches: {real_s_2 == expected_s_2}")
    print(f"t0 matches: {real_t_0 == expected_t_0}")

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
    # x = ML_DSA(ML_DSA_PARAMETER_SET.ML_DSA_44)
    # seed = bytearray.fromhex("885B7DF7CF6695F30AA3F1BC6A3840B8CA3101734118AE619166838AA3EFDBCD")
    # expected_pk = bytearray.fromhex("E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885BFE5E31A1E0339BF83F848092B623761C8DEADA4B6139EA700A1A91E5164B99357FAD504B095A74AD684E4DE51471D0976ED23E6D8164F7469E50478A91D45EA9CAF0DEA00A618FD60756AB09E617293DB9859C82EDDFF4E5274AF10019A233309073ED469F8E438CCD82894F6D1F095C2A40F05BBA63B58984458A202016849FA2A963FF6B7EB55C3D881AAA46399E76E2ECB8ED8F05F15DC60694690B1E7687608D5B97684F2EF59A24625C4FFA0EA6C3CF410C275E37B6FD936C29A803F3F1E90EA53B7516785AAC68C7AB89EF15562AEC97E258B30D7B3947E655228A5073232142FB96D4CD64C562C2D0803D109DB76A2828E0A90CF87EA097E3791105008B015E236FBBB1E45A19C8A46132EE13B651B81702C2D19A41FB3FEEE728BC5E67DCEB3236EE5689E9EDDC9201EA91670459596A35DE88552A3D18F47F24CA86717B77702808398238D59642A38FA10F6D17BF28DE18184075E6C4CE4B50AE2AE0D59D080694E13FD6500F96AB34B4E2882755A11ABB9F4F56A275F43329A6CDC6FEA7220F63D6060AA389E5328B4DE152A17575369A62EC41CAE80F4F7FE22EE78225485DE16AF283024604D979FBE7567C8A6184AE0C967BA5A8D8245E8CF9623B36574AA27E0E3F8F2F5D8A1466D4C45D17DF60FFC6CFCD9C7B029763C3139087D7AE8B61F0BF34A1E03261B44106A5A18C8655AD7740B335564B2C2DDAA81A52307D0ED0DD777D955C90DB55682F7A5563D68DCE388A41E65503FA2B5FCA33F636062DC97BF3CDD9201DC1B973A4EAE1B7A45A72573DCAB1029E221E9EFA2863440C4A41B5BB23FD457CC5847E80628B8D6F5E713789DF20350B7BB295344843023D06C793BA30F9C4552BC7579E484119472F3153D2621C948DDB9701A205E9B56ACBF08684CA237AFAB9DC9894B885B24AABB86BC22B8AFA248DFB776EEBACEE5719E93E8455132EE28B6C9F716BAE0B91F22C14A658AC1CC6D15BBFE1184890D5B0573CA167BF3F3531637F0BE6700E5D8B279650CCE11D5246097BCA3B43722396708CD0A4970DB56263FB8C04934AB7EDB97613276DD5ECC5555F45C1BF0405E83655D09A79E179C877B7B53750B2D6862A6D96B2E3112A81D52BD3A96D233E6B9825CC48205B344B3844D1B10469C4472D2545F9594EEF1340400A9634848DC5714F21BBA6B3D12DF8596032CE265954890B71239CCDD141872B4652F32B861A5E01B2E441D2D7765E489E202F79D6DABB09C082FBEF56A3D32AC30DD76434BE495AE13FCAB1E9CD16CBD5FD3E9CC50C25503C5141068966DB483DCFF107A0505AA3DDE60C66FF638C7F84BFF86F3BC5C2F8DAFF19BC8ED84A2DF6F39C04E61F77B0FDF1D9ABF204795AD545D80E7524508F221C9B80B244A396AA46FF0DCE813E704BD9C402A5317253E481A8742AE6B99A5D7F5BFC0D5A266B3EE57A84588F7E825419FAD1D30BF7F856585BB6CB22E7639CB6F02DD52CCCF9502CF30F4C9FB7A54291058F81FAA4B1525C9AA6C5DC798263C07922C428E43027EB4F4DB3E41120DED9A74CF1324B5E9A4612676134E650C22300DC078DD5B84611BF105703EDB7D64AD68AF62EFA52D8CD684DD93599ADF15EB2A0A51EDC60633741AD1C9CBC15C092C2717C619D01FC6E2483B6831DD8672B97FC0CC7E86FE8689D30C02D2B710AECEC599E0C706B7284E13174B1C1D4C4F5F88335157DD837A823488D0E1219A2D92F9EBFE7B4347C687A4DA3EA6026F96712632CF9ABE869812F6F12F5200C22C5F52E12E1A08DEC556ACAD92AE79FDB4073146D133C000E")
    # expected_sk = bytearray.fromhex("E657EA5CB1CE08341D2E59C0426796A8315C8C0373C89C2F5A10FD5667B2885B04EC298F3AA93654E01A33009C14A0E4185CBD4245CE8B5A2685DF7E24976D3A709BF64D5BAAA1791D413F8DA075A552705C11CBA7404420C31A291FAC5824C9176539015C3F03AD5E63646A93314EA25909ACF0C95F7015DC8446D063FAC8D6199650191125CB848122C83104A3092434615B442E48922452000019C160222484122700CC322D02C9408994292109428A42494A0262100252C01801081040A0C6908242001C2530C2340963986C14C90C18294A0A870104A99082A04548108889167093322A98288DD1A42801286142486219A8441BA5248120302222080A139109B2240226410B2888A228919C0892DC420C9802051AA92C04B35151168E18C044C4C66041808844B04DE488280042868188409142461C812C12286510250E18A60921220A14C44918B18401C70C80A684A2A06024468E18C12D82902C89B68914198E80148511C790D2C82918093009A170D1948C929061A0026C5426508A26821B494C92022D89305002886990184CD498491949268020889B40110C3584A2B26D9280450112485A288D82480C9A02898A846CDBB87022272521B5841216421B840DDAA64063146DC4C69184C8299236020A220D032445081385903409028089C8880022238A5A8050D310854A124EC9B46103122D8BA44DCC149160128840B6201CB9015904040433890B0802C18209A1468AA13289C8A611E0143199B00981462100B9611396441A982023258A4312489C36680C0670E43626E11290D8B64591B22918136A049501241942249471201628404662432848441801C12848A42092420425DC8449DB124E0A468C03274420322D0CB06C0B81110AA70C1B83710A312221497061A4609C3222238664D2C28D0C92259A94315A442222088E8A3690C8186859364C08438810226D22144C8122840B22520A2620A28048DC128091904DC1381252848413B771E382909A2602E4B0714B186022A5889AB6514CC80161C200CB465284C801C82865D230268B100620310DDA184AD0A208A23891C8028141162958B068432671C224658CA2614280290AC24920401042C68002444164846018A76020021013924814272D8B160A13C510D9347080A00DD9380843968192A24019B16D40423184A031D2442020988892947098064A0CB94592422C840084DB202213928000A38D94986812140694326914488194168289A46412A760B8AA3D5DEC680E7B2D97ED475A39EEABED483B48BA9B453A7D9D8AE851EF1F82FA57BD3F05D03180B744766F3132D868F1E61BB3529523F85C90E7071137BCC54FF472B378E664A0117451CE47F7234575082E8B66941DB645D27ACA53DF4056C6A79D41D8EFC3A27C676E83C43019CB56C8676FFABE1F924456FB102C2A1059113A1D049CE6063A56D7B0EA8EEC76674CB36152C599D78B6B9ADBD11FCA00F0B3E2165C6130029913ADDBDB64E5CFFCAA65EDDC272205949A0FC601ED6B31CBC710CD4881E4F51D3489BD97342FA8CCACF9B03F07D952C37217C057EFD8348534D0834B6537D14B1898D5C6644D20285A4269FB7D20585019ACAC0634C9A7A0BC91E595637F9B16DC454F38A1CB39A66E9D8BBA5C496644D0584CA0ED14A03F4B03901C82D6CCFC5151C84103EEBC22F2D190766C60C31F3F80AECF8E3CAF750E02D2745F4224C4F4390BE9BA43DA82B5B3270BCFC448AECAFC87EB2065C0D4C169609B78B3C4531BE26A84A4957A5E40037C4BA223EA5F19837AC3078CC5219770445A57A23B2255751A654A84A95983BFE09290A058646184A4019A678E0CFCC3169EF5CE169956A27CD987172EFA8F635B81BCA50C1F12577E126D7AC0FBCB0356220DA0BD2F3EBB2C0474CAB6CCE48D9FF58743ECA8BF0E3C6A85D045EDD4426CC33F86093BB76D946E36779D7E8C6D451027A826E8A8C2A1DC6EC5658DF8804C25F17D7C5BB4B8598D495A8E198BC43AA9B75D85F5ABE22D95788A59ECE32F4EEE60D30980CBEE238B314D520918E0FC73BAB0B8242EBF523B9CBFB606A68D7F8884DA73979BF826507F7A348266925C8D1168272F7851D5610034E97DACD3B014E0AC6A04873D1D1700E76231CDEB7E8ABC18EF36ED950744BDF888F958FD7A3955AEFF2016EC2D6C1896CCB4A6FB558F07FF180D786925EE1E818BED17889F7D3B0CEEA8D5CE41F477C4B6B4BBC17D1251A0E4FCD8F42AB3F0B95A2E060C688A6B912E4B7438C4CD144FA4DD2B3D7E6212497CCCD111033523BBC907EB29C7674A80D0BA4C27E24CE74998475A64C0FD82A45B3BFDF70971CEF736B1BB457F30D918337D7EA5845B97C1E3232440DC9C82140E63CF88EEEC3EA4B5BCCC898EF909A556FCE59D1D4FD6893D3F075DBC37F1D25E54A5FAD6B647D2EAFBA16CC4C47E253EBC0885E5587BCBDBA3770082864899654722F29058B8BD14C739463B340962556E9FAB20F1B81FC799D083BD2839C9FB220FD28F0319F64512EAE81DEC1952CB9A74976F42E67B72533E68651D1D4437DCECD21840318E4BA3989A965C8671BBB2594F32797EFA3EC720CEA86B456361819E9DC13C54381A03339F35856D31785CA4B863C0E896ACED0016FB4F0C7ABD5C6BBD0ECC8BE62A87589DF02B6AAF03ACADCE4B7B72B9F60B9B1AA662B96A13E10C2BAE862F9630C9CFE1FEA119BAE1AAF0C7DF95FC08933923ADDBC483D134C60BA303FCEB4096A389A333381DD8355FD3F39F9D9D6A79DEE51282A153E55E5823759F4B2258E7CC0DCF0D41B40F76E3435A68DD7E92A27BCE126EAAADD224A049FE4F920BBCAFE1A057B29E9B9E64E64455BA54140BB4F0E4D4D20507C493E17AE36C6B6A36DD3853894FFB44729721714ABB859908D84982071137BF5B359E3019A7A267DDB333D506DB8A918C2522F267B5F4700A9179C7C0668CFB0BE412EA7F4B36C74A1761C50E15C5D292B59E9C1E90BFAFADC8C05D7146FDC9DF78777E886A0402423072381FEE790F5A0A5F6B64F3BEBE02CCC98EC0205D30A471EF69CFC22CFC1C529FFC3959D2C57CA744170F3E95EF0A9166C67A4BB41BA66A9D46556EBDD2E8C6044EADB0BD49E298D806456062CFDE32C017D881629381BB0B93C14F70FCB9A48E7714B9DE2E3F636BFD1167E1E3476928882B333968AF9F3953FE40C51DF6EEDFE056CF71A962D936A821FBFB9191D60096C27CFD8F92BB64BA4D7B47EC12DFE0BDE1CE9E25BA50B33622BF347CF09C607A60C9AE80646B6958B8A5873551B4F927653ED379349D3382D856602722DBED05DCD0999CB88A20E04006B3E302E165B5AA421E1C4226C19EE0C75F7F6CD46DE0F243F3367886CE804E57CE16A3DB51304DC2492649CFF16731FC748516020C7B2AC3134B75EBD685088D177B7BFE1EBA595C798619476B8B2F626D3837A0397A777A84AAAB4E998CE5D1174399BCFE5C5241E5288A241C4B34036F8B30C0862DFBA419AC96DE6F4A0A5E3EEDB0532BAA2DEFECE28B912D6F50707F5CF743DDE5BD33D98E9108FAD9E83812F0BB143FB0F82CEE14DB90531AE1738978BB69C30E7488FDA9232E6BAF117FA45601E300")
    # pk, sk = x.KeyGen_internal(seed)
    # print(pk == expected_pk)
    # if (pk != expected_pk):
    #     PrintPKs(pk, expected_pk, x.q, x.d, x.k)
    # print(sk == expected_sk)
    # if (sk != expected_sk):
    #     printSKs(sk, expected_sk, x.q, x.d, x.k, x.l)

    # "tcId": 181,
    # "deferred": false,
    # "message": "97F51A22032B01133CE41F0DFE106A27E71F0F0EB7BF65F83ACB32595E09291AEFE8AC96FA71B72024AC08BFB9BC7685222F915360332A438B1494BA4C25BF44A3D9CA75968D5779727042E202F10DCE857E7F1D4ECDF4B95D422451EA2990668E0AB0C78BFC04A24DE02054ED8785AF667FE3DD8C4D4F54A055719A2FA55992C4306988A1734E695B0B6B9D21940FCEDC54F644BB5597F893523AD96560AEB97E42E9FD5662035DC39E322346E2A6DB2FD6FADD5ED7D4AE2DC0EAA5D112078E2FB280C86F3FA5D631551B8F03C4B87DF70CEB6DEEDD6BFE0B583CFB3835B3DF2E36E7FE609EE71B44E9BBCAD5DF0669BB23DA84F136C517B1E167565BE9BFED20F16F0A2E74A0D291DDA3B4F41CDF72AF97E4F822D3D09E401673017078F8E89DB0E7B552B501A01BFD58C1D4062D24E2D7CF54D15C9D07A7C1BF3014BCD0E99F78BA2241C24A7EEBB654C0DB775F004688BD4062986057D228779C33ED566FBE3439340674AC9F1831EC32B370301E5EF31D6B2B8E1ED8ADC196ED6262AFD7E808300C96BDF463F4E9CE80700E186916D9FFE3C53F78EE40CFF2FBD7A089E7B15C40CCD947F85DD6E2AAA47C5FA8A0BC6E8EEB4A613429D409538F1BCB469E8D4BDF19AED4D7A5C54944FA684DF7945F0EC61E3F16329176EFA1B0ECBEA61BDC13F174F307AE838CCE027DF3AB1976BA404DC2E723B27FC0D3215D586473C7C638A581C3B2D4ACD0AE41F296F365974DF91560856D548195B527C8B47E31CEC098705942666FCFA0D32F3BA54734E79CD6DC8A3234603791E7E833827580FFE9E63ACBDA026D29834794E6A4E5697DE8A93D347E1BB4FA644A5BB090F31734B9D4200EC51D90DA0A5AA5E72FC581EC98782699A939D40AF5FFE96ADC7884282EC3AB26D202F60F43E76E5225A9FA4DB53828141C46F865FAF210BB2CD4C179ADCA9129123724C18C43E0A19FCFFC06BB163F9EF231F3C0EDBE5DF6C3825223890E2222B0B663F4D61B450F06E52358E9D43E7FF74B88CFEC41E0762BFBDCD252E687C327E6DAFA9536EA7A01DF01CD3589F29F55A50A10D14A088AB1F92BC09547EF07B258E1DC739324025C5919F5CC916F57BC721942EE3A1B09C24E8EBA3946D31BD5CD5FA4E0AE116EE7F94BED53CBD83FB364076962C4D512FDC28B85020CFCA7466DC1A4D123BCC3DB7C06C44C19CB4ED391C635EE1989967230C89C72EDEBEEBE97061F19ACD17A9AF583EC5A4742C65EFD72EEFBBA3F4C8CDB51A29E56B95E68610C8FDF2A4B467FC2F02D661571C4D366F32B4B544FCA27E64A65F2503C8B23EA01CB0B152C5229BE424A846633D74044F3DAE1DC486A2D17A50C7D7504C20C74949AECB108C641D50794BF7CE2CCF2C7DBF71249FFB784EE7D14DC6E27315301C76633269E1B3C0624E193CD59AA2C817AA4A657C4D4DBC7C08BCD44CC65B79B6118270E4E6D6C814FD71EDA7E447A4B58A8D3DECCB41AEF7481930A9D8BDD42BC1212D3F6852A4E83730CDEC3504854956BCFA9A873AD74EC1D9378BCEFF55BB5E12BC79910B628527B527A29070D08F94FFA92E79324E7D9ABE4ADAE7CCAD6EE35E5D05841A490FEB73CCC5B871FD0CB41F486C6E3919BB283083DA0B5E08E48AD0148D7D84AEDD6C075792ED66BE2E884628E0A1283EF7EBDA8A22F7A5173306BA2C66908552DCFFF9949D210595B2638B8F12810F9EA736B512D0519ED6F0A48898832911BA1768B9E04FDF65BD0EBAEBC1DEA5BBCBAF3D45784A9CCB86E0496402DE04409E256A24CE5CAEDBFCBF0FBF9BD87F1064A766ACC3B737144C37069F1BDC24BCBE46B440EF0A53225C010CBF5ED8F28D7F6530279AC2975266493F218F0ADD096E5E888E65FE7594CEF16F5B19AD6D7B588599F8D5831B36D51A3F64AF2223CB5C166CCC545B03195E15BAA5F96C7CA5BDEE43A2C6292FCB2AECE96907D3BA79A768C786532B69AC385021F55E3623BE83474869ABCB2413ACBFE7CDF74B69700B08DC1D1B0FFD0647FF7DEA4CCC8B02AAD0B47143B5827385E2865021B19BB64A7EC1D938CE9F37C89C1F2E4EBA062300097F92F1B3EEDCE214EBBA37C592671DCCA442FF9B0C2A63A63532826488719CCE15B428B972EEB1B17434F902EE0DCEA192D72B92F125BDA84C64A2A08E5649D4BD25C36118A093DFE5E0C0C9C2B00AD7E310BAD24659E3E915416A16BEA79234FEBBB2F8D5B1C24DA971ECD51ED2E9A67B5158208B4890701E9912EAFE4D41D2B5DF9CBC5686393B31462AE6C9F282382C5854007A58049B68197F0EECF383D458A6D7910B060EDF61C2789FE408899DA80FDE8211AA899D70A7B255659B0DB9D60EEF53902A380ADA75AAF3F575432A7EE4A9EABD69E3380A67CB4300E9551CC66E153723087241EA8BEC04E284053BFAC34EBAB7C417EB46125C027C2286C67A9D87FAB13DEDBD9F51BEC545295A567A376597AFDFAA4E68C67510C611939951312E3CEA8F63505AEE8A520280B1BB3312240FBBE7F7A8CA627A249E48AC29A3B15606D48D789E47218FA77874A0E2EB0369624B475AA737F2CA532DAA81EA9602C6B363ACBE9C746F57169F3F9B84C5A7DF1023323C7A74B9A39329FD0D9E382EE70409668ACA239C9477B1CF60DB85E4502B48BA097D16C029EE66E23918D718E6001B217915C317DA2CAF434A9EA80A755315E4A72E2EF235728C5DD1FDC943BB0C6E18E60B37660FEFD8286F4C42A63C38DFF26C92155418F12CB08BD2F7B2551E8F8D44E44355457276BC7237F352230820C9A01E624A99A2FD29508CE886AC5A6062AE75AE6D028000DEDCBEF7062A7D4D6469940CB5712E02F35145D55651436B794E1DDF606C8A6DBCC3E3789C964E7F25E339DA17C3AE707DD61AF7704CD4B2454B9D5499A320AE33ABC063F1ABD91E48C6223B0398B70692B772911ACE198D37E51475A49735482E4D62CEDA4127F07735B599CA0CA769B141EBDEFB4EEB967AAAA529AC40440E5FEC47AAF278588E867DEFF6548427DD0EC0C5F895853465F8653722DFBE6E572C1A2DF1E9A62A873A81643FB4D3FBA1CD74D81AA760287DDE21512CFF931FEAAD94DA5035F551E6DB6D58CE031297498226C5EF991BEC067A53E74B8D05E4934F67424C2D7DD893647126837692D1C57CEE22D4365F41EFD107DE1E88B65801E0DF50D4D80437A50AFC3EEAFBBD1E48626001D507D562A04C1A406522D38F935C224084EB44257EC33AA998FF8E0A216D00E20859A43421543C190D82FAEFA4953E7905DE7B5954786B893C06C6DC6517D350028814D1C5382F0034989DDA4C76A06FDBE321F4CD136A2D3B796C406470B1AB6D375654F51A6C27D3486CCE9596F2A8572B5D16B3308768DD19EC315FF248A15733714F1EF79B2909E525547C473727AACC42AD1218DEDE76755C9033661D089CE905DCBEAD6499D86F3F921F0DDE39AA2F977CFAD58A6D103FEC83916398397744525A70E14742393D829C85EF1E52F8EDF3DBAF844CEF3386BE05EF9DD75B0BB5812D60C717ADFB46F137C4BDE3CE35CC1168CE93EF0861B311988F42893A75474A69BD442F0A46C26F9E9CAEA2551F4D4878C84CA2561F3E718FD16E606AD59DE67703031B7E44E9A560EA0E46E342F2F6FFAD6EC85BBE5D7CC8C263F3FC33599CD381F548163CE5E7909860A39C0733F3D55A93B47261686C5B2948642C8A3DD19DAA4E2746C8519361E129C42AA8961126807E2A04E73721A93C1077D047C8CA5C8B5C32286A845384A8ABB98311A86B9118BBE5449A5CE9DC7681CB1BE63C0D9ABCD5D3043739D275C2C461D113983B072C5E0C555387326E5069524CFA16490A8CDD2B5CBF87FF250138CBCCCB4A45C8DEC5323F369A67E832829C265EE3BE9E812D1B696119CC5E9D42EFCB6F64F0FC9FB130A8A4DA27A8369C668BE68C67F1043B31BC36E58A1F6DD7196E32AE74991E72A2C6E4B2C9B2D9524EEB293A35A6B12269E3FE0F7F4278256B6E9D00FA75779FB62C2319236E1F2FBBA627F234C945A67F2D13FC28C49ED5E00810D8E2950866ED6E037B5D204F8DD026D41E18583D7C478F95F2EC64FDC997704962EBEF568FB4305A62459D3615200051169E3646297B0CC84914CCA747D0591883457F8E214D62546E81A8891FC8BABF93ACCE22B0038EE26A1093F218AEDC1ADEAD0EDFDF940DE4B0F659B85D76E8DD06D55623EB27C582155F123F22234AB83A05FFF8A5C184E9D0A94A7595A4318C5FC61553671620CEA5A491648DDE9E0B6BEF5C8EF338932C28BD3A0BF67B36B6B3901DB03EB6978694F33148EDBD970AB540E0CC5AE52C6D764409FE9CB5C1E6FD8F1214E9435C5CABA7742FA6196032ABC6C1B8522435D5B4F7038B03432E1912E7525DE042D1870942F080CAE16479CF1D41CACED4CE4FECF267BACA559F9C383F011A933F4FFD81909D107412D81CB1DDD0A2EF565823F1E59D30305317966364A3930E2647AFC021112708C0357A32A81DE1FBF300DBD20F30DAEF101EA2B795D0A99D0AC4CFBFDCA5F0322A2322C07C405F05CF3C441E309DC2E5F78C661153413BE305E6730713A138372F1C7FC226D26B763005F8D1C3BF738DCBE36104ED1F5E99F559A2E7C69F1BC80E07CDB41B8ED958814320B1EB314CA8DE39963F79464EECD09B50F03AFCC960B7D403105851B75212DA4B2C0C2F255659EDD4900FC3AC11282605D2E0FC32DC7F3CD100879686A2D995F315576712D66E31FC6DD9489D98E48AA6DEF490F815EFA2931F059388464BADD89D6C809BCEF50A63D902128F124BD6A40FDCD240A2335FA5E33607E0D20AFE80586AD97F888A73B145332B758585D926E6758344DBF64376DC192642A64FA6F487A804EB62CD199311BE46E5AA3BBF0978BE2088FF86385D564C3CA22D956F8C28D5A1349F51D5070E82CB045399B318BB43E815DBDFCA38ECA44D47D41815DCC29A8F6D446A5D60C3FC68C9BF1501938400CA43722226A832F5AEFCB2A903674C7A29652D472975875A37F287FD2E9B90FFF0E78F6256EBFFACA46DEFD4BB0BFEE0C6EDB0A28374F849A5C90E2654E7639ED16DA502580357DA07A0CC11CF3D234618DCE4923A725DA5E9E775BEC6074D708FBF11DE4217CDAB7FEB14E11AD2211B87D42DA257E35DE34BE72A25BED7C52C81D6F3F048AB1A467F4C758855A98D140D24868B23DF4773BF5A895C6E4CE7E5637A8AA7F63E301E6F5171AF570D3DC543886296CD28971C8EEA2E88B979A7F0EBDC85936ED09C7FBB53B3CAFBD65DEDD332D6064DC3C1F90DF98882ADFB62132C6D75B4EB1108198EB06A8F119506076CDC741B9CC46E518170B466FA2B2025D2D56FF1DDCABA575E62CAAC254379B26072ADCE1134E88C6F537F9578568C595C9FC29B47668A1A9A95508540DDB4F1162CCD86847CB5A560B76857E544ECBEF81B79DA448FDF3DF9224AD6EA5933C7AB54EA65158474D67A071B2694834CD56C4ADE849550560081E30AF9532FBC7BDE0CDB322A58F9C6901F3AAA806111042B9DF696D511D4869704BE1F4B14F5A4B1AB97B587787362D1A39679E6ED054FF2560E48D46E2765B262AA9DBBDB7A3689218795B1135A29E6DB04FC7796F9319279EAC54B8ED6493148C8E1925A4DD6A01E00E02EA7C9DD1B49C7BAA768BE8B443CE809A21A449A01B64D8AE07573BE85AC5536123D6E8A739CEF8018E7FF7EC3B9570618C3830544132D9D324D7A0AD9E09296D77234AB4300DD351F98AD2F437FC86A704D9F28433CB856E8B18B50C20F18B61732FE9C13D753A7FBC631FC6A064ECD9E3C09F2A6A9C9D61E5872A6B8C8FB51851735823D66A68A3035D20D02C6AF6B583419BD50ADDD4CB53BF2BA5193EDCDD344C31971A701A7F96AA073F68F020102D43A9686CEA65820A7294F1E9FE4E0B9C89C14C7B24F92DAA08C06F60DF3EE7B015A4674A7866F698ACBB139EC487561A671EA7D7D026D1ABF4E1D2E0FE2FC58632B671556873BB31981DA1F5A4228BDBA06E8FA5C4196686F9CFBE34978EB64EB0B7C05062F788F7C36CF137ACCB7AB2156A6FB47D763DF306D44DF06B7F9D89544EC01ED5A14510220D1B020C6D5B46BF29B335180B9C71D695F1A807AA04DF6EFDA408113ADCC99F88BF1AE81388F87D549A705F0C87F956D258B16AE598E22704159565D89B5A991241A004F3442F465C8EA08D2CE3849309E0AD9475DCE128C40D2C42CF540BF4289C42901A03367FED2646C6C0A634315864BAE390823655D1BB0729C41D6DA35560346114DCF7C3C33D17AC31B2E3CB37F05F3DF760555CFE576D12C6FABD05D37879A3726C22B8A1B144E5DF34AD3ECDCE248122401BCE04A6CD369499750823F7E0DFF1B09A5B72827E132F5A03",
    # "rnd": "31CFA3107E691B2BA6957F5DED6D2CD9BA9D5794DD897C2CA2484A8021E9E36A",
    # "pk": "42D25F80F14F915DDA55C441E9AE33CFB7FC1CBCFABB578B93B45AFAD65F8872C8A555D716EAF335CFC946EE30CA2FAB105E5CE7FF257CAF24760C5A70C075BB108FBE6F4EE90B863C2A3117386A3FA8BE53B16980DE5FAB05EFDC81C4FABAF25F54B25293E513E43AFD7F3E4997C956FBB64CB4D5F50D7ABE6FF922FF2F402BABFBEB93E040404A378A826DFDE9B6F2083EF101E94917C963A1340A618E6A3BDEEEF343BE151AAE75E63507A24867F014B204AD1BACAB6580904FFDE8614D986C4FF6795AFE9DBE42EE0E55B9581D417CE31B0E682CA4F8BB767EBC35AF172D906C3857C5AB59705B9A99290F5BD5095AB513C10638BBDE80CF95D9D91A6EC5C871BE0E7243BD68A9AF8D094833F0FCE0BA4FCC738D94A6496A2701343F1197BA295124171FB2E77C502319ADA050CF39869DC9F4ECCD46D19881AEBD9199E215379079457E1230C6FCA95AFD251AC3606F3C7EAF4977F4F7ED1C1DD90F3033EA6E2E5C761CE35811D703A718C7E251718ABD9E0CCB100C299CD850E85EFB841C3A78408C36C937F53553DBEF37E6C6A5ED6E796AE20E0ED03EE2B7DE0689A09E4E354E72F2FB9E8F0012E44F09E23164C6EDA719666617C9F97C6B17AF7038BD2F3FA8C8A3981C1FE2A2F7D4C9825478E7AE7652BD515AD85B27427E92AB803EEA5C2B94B5A89F9F4744A726491E307FF5C7AF6449E0779DE31B6A2E3AA6078F1D9FC12345D5741D7F4032F1AB32DB9D4D05BC4DE9AE46A7F6B2F1EF108DD9C14A178B7566B4A5F4E42BD6044B19F1ED77A6CE1EB2D7E23D60608C6763DD64B4B9290D3E58E25746C8F147054A98C6BDFAA4618EACD65975EA8F6CC978CBE59A332FBAC122274FF4D091DE4C14119984452154BBD24A2DC8F871D24FDD4D1A53927CC36E65D5A56457B15B2DEC14B739EB24322B333434E5AAB642EC78286A45F6D53C630F3DB2412E82CEF9B44E99683204B39E7092D46B236CCDD746DB22E3C74032AF601FF20DF89BA45314B768110577D47CEA1E671CC0DD7ABE3BBD0232D0CB6D9C99225B36327CF6DAD032E40EE40FC2CD1ADAFBD07D913191D38330468A874F71064A42A14F7F2933D3BE89AC00D465DAF35497E1CA2701FDD733C5B552660C9FFF9E4E919A55065E04A557EA7FF06D6DB8A1B2E9BDA0A1EFAAB1EC60AB9C87DF083AE2723F0FD504A758EC6F778C34E281813E4DA687F0C11C7BD40A545CBF3C4D05700253BDFEEBF176DEBC9F9165537470C78DDAA679E529716A6325AF79392EA70E369908B20B9298B7F504337574E95240472D79B3E087108F11F72C616489D8E4D5F638B7552CBD1629425D17C17B591C8F65634A93B21BB1C5EBADAA1216224B0D9AE42D40EFE24AFB770406E93CCA6EC969054FEACB268CE422AAC3E55F4D1889A17D7FEF1B8D42C29F729A1A675722FC9D0AC4172AFF42FC8DFFC25493E8C4648CEAA7ACA240D25B63C4D1BF78CFE0BD15B60400234DDAE16873FD17A90ADB45985F727169A270E9561B67ED9ACB8C9191789473809C02F198CC26CAD109EBA38CB3C6B79EC9C3450C551A7BB737493DD1C172B83692F3B8F19E229D07C6DC409C44A7F4C4DAD8C3AC6874E811A62086A14D9187F171C5B1F13FFE8F6DF5F4EE7095DE6D62861A49FA74E2ABCA6F2D712CD705A8B86AC4AB28B7018013A32774A6620475C881F606D92FA13BDC219D9BC3BC034A7A0105826AEC53B3CE42313F7B92BF17158FC690FF401E3D16C398FB71DE0F9E2BB0880777D5796B718E387392C2A4CC512C694DAEE1C8539E68E93E20767609875B408E806D67E2532F5B0CCF4B8A5FDB151C5A98C4FBA6D1942E3986CB02BA72CA9D",
    # "sk": "42D25F80F14F915DDA55C441E9AE33CFB7FC1CBCFABB578B93B45AFAD65F887223F61354AEA9C590B30C452A7B926E00F49CAD3F13241CD5A42EBD41161B895EBFFF9232CD0A300033246E358BFEBE6656D2A6F465FC4E49D4976302FF87F4E747EFCFD316D7BEDC5888163972A30ED27279F41A6CDB97BF38460A3B2610436FE11224029870533621548480DB402E1C904912110958C204004586180410CC4824DA266210B860618061C2948D2447505C42458412660825450A49725B862900474602B48502B6600BB5419C860808A2849B184901A19000202EE0204A982452948630D0948999A05014A2691024450B318D59384804384153048808010418354111000992048904434C10032452A68C929668DB2226D2A80114416C5CC690C0300863966411B12019885023436ADB38100A17891C332412220A498284591032E22488023824D8A62C922672211661109970929611E1B86D1C25320040108936022346298B9821A1C26904A78C101608C196104BB6640131624020620B416613458453880552069012228949042D63060EDA166D94420D43B80590C004901204A0182919462D8BB62D88C0250C969094160E1C94480298288B38921B290A118928D8324D81A0511B260C600650D1A83001126941B210411429124826C4860913422409058510C5459B002402426588A24813B46C8A302A8CA864020308641031D1122CC9C8840C3420D1968C90C020DC92041BC64502474C19138114024ED83285182086023524083305184281644606D9167114B22D62320AD128885A92300C2968DA308EA1984891C08D23A34422085094B41054464643204CD9060A81444264B0810942529C242A8890899C486D5CC0115310458BC86C5A268E18154E02465214189210124C01046DA1C20450444C14A31098C4858A38901B19029040920A0949138804C2362E1B291059984C098585DCA63104A9505C36125A82808C18801AB421232372DB244519A609C4082414A870A4220D0424651445909C804C62B448028171901261210848A308200A8064D9A42C89144E60188A4C264EA12842C81269D3320A9B068190C6602003200AA38120380DC9C860DBA611C2888194C68501A7404AA21011847164306C8B206064B8919186011B166211A5402446524202669902426340258BB605CA848D5AA0201327520216610CB380C99224A1080962A481C4240EA0806504104598A82950989104136D82208D9090109C4051142312C59BCAE3A64980141D561DA0EF260A5DFB56040E9C03CA9694E7DA85ED368A377D16D7675F59C59DED209C7DB4E96EB24B7777399EA0249DD3B9C951DBE86D77C6BF376193035EF1EC5993503E6C8A4DD87DA8A68F0B0B536502E5A53DCE57644330FF942BCB392A4E8061982A6D48DF6F537BDFDABFCB2F9036DF7844481248757993ECA397645E2F9FCCDE5E66213D6109FEBB59A45D3BD5D6D3A6AEFCE4C0A9D940C855CF5AD44AB6D9132B0CD0AAF2D99FB668B6C10B4132E9FF232515BD1AE4DA2B6F1CEFC3FF8D41982EE8A66D50FC303CDC61C010F87B02AB79051912F82403CDEDC73FCDCD5D6EBEC7EDAEA1E3B85F382FF247B8C3E7BB1D9EC2658C03926CCCA61B999547FBDB3007682957D6438638211EF34D24831A5DD74A9AC4708A19C11A191023A903563D776944C15FF025E362E9114F3BFF32B4D91DD162BE71E6D71EAC39F294C574D6DE3C3F348106E1B97292BDBDAD7F04759EA366A01F1CB8810E399DAE11DDBF53FDC67F2EC3E1FCF208B91E8979DB1C3915FC529EB5BF98A2FDA3B50F6C34DF033E33F07CA374D9D460A0351D4D9E5CEEB169F176EB25E30BD40B54DABA066FB9DCDD02CE86E5EF445BA5931115CF20AA4062FF2227BE2123E3008AC0CDD3C3C5EFAEE14B2A8A03C502D74073277ACC2F77EA64A1963BFC24DE56FA55A8957ECE1FA8355CA2086146C2A64A5606A7C93D460D145E45B2BEC7CAE4FF5B8EDB96CF7F60DB47EDCC010561B9073C9623A4C14334643A4A377FB2D892DB5E5DE2531BC3CC716C4A04A93E4EFEAA07BAB1E1B82AF3E6A65AC1E4D20937A4031BD2E4F5C95FFAC0CAA595E497A049754AFF28D9F44FBF73CADA7BE230D0C7144B6C13BE1D56B490D5549A6C58113CCA60391C4062D56257DC54BF1C1C00F2D3655F96B7466660B7F761243A0CBC260472C5439B07F8A4316CC227AEC12B0BF0D7C3CBEBB6F861C6B6C1FDDF258CA80921F570278AB4CAC743D171566560CB9D962D69F7A5954E563E319973CD1801BFC4B5C7601A544E7ABEE1B223B08A525E82B0F45D39400F14BF030F7D8DC3A2E15BE43F087DCCBCA3CE4132ADECE0AD28E9076206C777F648B26681647D4225B0093D39E0C4D802E1E6A82D646961BE32BA5427F3BFA1677A4C8DD52102EC6C732A9F4FE56FA856B17EFF1F95C430E7798C418F192A131B8AAF6EF98F3686B20929D03CA1B7309F471682CC01D13596D628F49B626EDA90B9C5E19C5D34FD888E045DAB9E96B1402D873F1890AFB5978AF7BD872147602157F5F73195668CF465F4CEC2C683C7EDDFB78D4138C6E91CAFBAF34333E2FA63B4EAE4ACF42556EA3EB25C0A05915D9C8FA2AABCCD2B4F4C9AB2B288D09031FA66965F81906D3CA447EB297E940DC7B4559DB73826538A86475E03748453E7A4DD7F2E69DE633970217CCABBD0FFDB71935419EB7B07835E30CD6CC56F9761133CD49C63AFA8D6DD2D98453AB2CF54F8006EB8F21DFB8123F56E6319E12843880226DC887276782E6439027BC506576E33DE561966248C98F4F61EFDA02A98FB4B2FB9E90E95C718F9FF1C8ECA1240B447FFEAD5A9C1B205ACAC96E79132603753C991A66C36F65EC7367BBA5A7AAC4660A99C736A53FA047C7FBF495FD0D26252C14F28BE375F519F52A826E9D2DDEE8647DC6D1B5049A08876B945958AB746C41DF923B2725849F21C961DDEA6CD05A4E2A035317DD713BE6767521BC6D2DABBFD7F0A388E12876A076931ADE9D6E86B5BA5A38F91FBA1837D40FA8FF9558F5D28EA59CD050F2B891EA0E682EA17EC4B02152FC25B32041FF558455DC2AAED45F31448565152142A58855608DB49F1C0C355410BDC1838D74ECB69D2B365C64B3AF293511D6F39AD1DBC719DE9D4192F495D9153386B3C0C86C1D341482B6A0311A3CC2044CEFAE324E806E11219D04A28CF9FC06FDD24E90AB5E95A78F3110DBBED69CBF800AA2ED8D2AC44615AA61CEAF907119B1B61E457836F1C93CFABFB85ED16DA776B641732831CAA5C0EFF048A702F03E8414C34B95846CE9E80A774E6B20493B78CFE686CAF8CC08259FE4AC3B59E3A3D1A6203C3DA4C37F812EDBD5D89A297E96893F0DBDCAA5747166EBB888401EAA5DBEF9EDD86FE446859DEF6D268DCD3A839FCD1397CDEE756802BC59D5859A90054A90414EC51A36705EB8366576CE18515373D1350AE72161FDC948A602D1D27BCAB7B7B212BBA31014BA0E229B17F8D875356A93B2D98AF49BD9C0587D3AFA0DE480721B277B51CE0DFA91FECA620EEBDEF2786241DD2DA522B1A0396E7E9997BA59E0D686FD82D9B334865370E9B326A280670A945BD94328872",
    # "context": "",
    # "hashAlg": "none",
    # "signature": "13F9DE5F0FF0F34E4997FF0948397A85D3DC6F0B274CE253C49EF15BBCF337330FE0FE09F34739B0A25CEC983E41DB03BF83E800E9D12AD2F0B79F0FE64B9C21F8491A719DC7DF52203A46659B9279DE25D1FD356BD489465D7B225AE7780E72928E85C2282F6390CD47A9052BF90979D4B354475369C40106ADE1466C6FC4A828BEA575AB9399E52B8C6374C4D0424F0FE5C5D2ED0FACDADC1C620C8F279129299A3F3509421E5077ECF90F4383F4D682DBF5A37507A6EB50CF0701FED313827E66737EC1328A02F94A743D638277BF3593DC514023D385C7D771F7C8ACAAE4DD01D4C822B1C68B2DB1FA3BF22EE059EA5E3F1B6BA11E73A9C955C804F726D2D16F3F4FE040E6381B5AC3EC38BF4F8C62D5D3CD99DE68691E16C63A341D6F9F1183AC12B5876186C81674634A54766AE31C9A081DBEA45234F1364A11EDC9461063CF03CC141C02269F73E8FF71C36EE483CC4B3ECBBC7011FBE4E7BEE2E0705623E7BAFFB7E41802A0C5B83583CB6720CD53C93AEFBEEB08A598F983A6B720606943D76AE3C64354E635CBCA94A0E390AF15749B8C3739A93D61BA63572A20CEC7FDFF78AC6C523B0BE7E9ACFAF1395261F400CF0BD25C045D7A4A059A2B2DA9647DD4EB97EE57093BB0E8A0EEFC7A8E8C202FFDD265B78637B454DFF3498B414056F27492EEA3D69AE2208D9144942A6FCB466481A48F66F6BD13C30AA131BAC0B42FD8D2B384E617FC60279A4EF77E1C3FE251130641F3E1224009EF4EE7BFA80F78C7B9BC86F7178EAC2F8F7D2F856C24BBC052C5CE45B7569C8E567D44050067A4CBE39FA60C8FEEBC5996997E8622557B9F960222A6DFADA06F09B890D0F7554CBB99FD7833F58F0EB650B7F992FB19E95DBEA49EF504398D718BC4470BBADAC04357A52175B4CF5D2AABE3505F726DA4CE7CCCDE6AC7C6FEF7F7482E4208773DF16DCB459E2111CA8BBF673BEC6F6134EFEB2D8B5C57C837D0FF8C1D98F357F84481E921B0784A133C8ED74B1EBAD08E5B03A875F233D2B3D06B1655281A941C83FDEEB54DB158797FC24866F595812B04F63E925930D5AC97162F952F2D04BAB31E2FF791187D990054B41B3737E44823B0E95043D6539A0608CD9C2606D95DC68A643634837A682AF5248B55042D1EB533398C4661D85B33450770200F120BC6D1889A7C6B05AD6E2C5B82E255A556C857A129FB23D4C94C6F9C09A4333C9AA8D84CF22DD2837DE88591473A54D3634A0F2946CB9C6BD31CA39AD98CBD31D72FE5371BB918944694A55BD90D6ADB441599C1D820682E4850EB1699E79B6D11680CB052320CC9FC6A55D5AB0F3F5245A31C7AAB72C590A11571CB723F13F1A7E2F895B56BBB880E4E2BB589EA9EBD4803BA4B403821B5AB3CC67F208E7528870C39EDCFC3523EB5AA7C6364A81BE85BDDFE9209E5E8FC678037297EE336913B82955235BAE92ED07EE81CCA878ABE6D221CA4D89CB86301E9CD15C7A86E00A75BA90560937CC5ACA9630BB5F8751DFA955B67D36CFB1BD0FE5F80D443A2AAA090293ECE68D49E8B36B1DA2CD814CA8283DD9F3703B6BBCE192F3DAFA934296390F4C57BBE6528F5865F8C23D5B31BAE253EC6F7C4F51006A08C7828130F61C4C08F4D09658EA9F7CD2788EF95AC3CF2A2763D02372FA0BB974EF7E8EA2FF5F079E23D19C903F4AB63D04612D26BD11D53FBF7AE673402544F2044CE9D407A27A69AC4DD37042786ED006E71541FDD3314312BAA2194198D5FF9E1CB043059FCF2B7D1A56C29EC1D15BC85E6C238B6B13630884A4A72FA321AAA781208BB0F6CDDA54C132D80747993B4C631B0D413CCD70FE0EC1DDF1DCD9A88869D175B3149C23F350A0485C95C2BBFE5E29258793A0E47EF89A4C0B44FB93F84EB473BAA6C7F8BBF8129B4EC2DB9C63F1FCA2B9C432BA9F37E9646E8BDF0862351BF5205D6A6CB412431D3E5CADAE0A41E75DC2CAA71ED3364A935886A824F96051FCCADA3E99C1DB5C3CC8540792A41DF6DF7A4C82B4AE8225E1C9C071F06C3C79B1499367048B53AAA03B024453B774D4BCBDEE65752ECBBA11394E62088F1E4124BD89BC1DA4A607F8274C434291A19984266AA80556EBB667D70FBCF97147AD7809C1E1278C950A470766F5A141EA85667EFE8C15CC16FE209AADB96A600229E2F9CF64ED65C20F572FCC8F01D4F96EF576B316C9FE1ECA482F5D6C119618935B112C29176EA6740BB01E7B5E2A491124806D1C1E973D1BB2FB46F1091C0E129846724CED46D48B14D5B57E6615728D65F1FFCEDC7FC2E96A44876B8D5ABAAEDEF19F20DB77EA83AD56387D02205BBAEA3D7A5BBEFFC20784E43B6C2E00AB63943E7E3EDCB452E77AA426AB22ED8673BB0267E17A5067CE65A9B0A9BDF25E40A974BBA8EB517676AC284E2EEBB9B3DA7C0EE4E2D1CF4F18E5942D46AF07043D618462F31FCB837CA4F7BC35505E937EDCB93AF0EE82F56DC2AFD1D4BB377F61A9A61F0857F2ED712CCDF6C353E3EAF029A69DAA02673707934469E629DB442418EFA20E85ACF28714DE92340FE84EEAC073EFCB28A779B0C9BEA2351A12924EF5C0C45C0E9C2DD2B3EAAEC6E4476B47D75D4D4EFF0134D6363FA2C03B6D7BD69AE847D7E9D97FB8204668871EB19DCDDDB7B4131255AB31A664000633FE9B9C68686895D3256ACB7E236226BBF3339991564B334D202D6D5BEF1869BB3BD69262379D08619795AD0D438C77AAFDB6EC1F429946C8F76BF8DFFB285ACB9471E503BEC49DD949AF10DD8F7E1BD2D0DD3F8D78AA0A68B67B9FA374047B64C449C4C78C1953B740694D7101C7FA3B0093F56D56E98E574CA5B05911895E7B4E1CB3AC66CF4EEE19FFFD1F03870864AB1563738C6F232D7D749C3CD8DC2283A1B61CB40EEC043D34DD731B63A7D0403A7FFD7E11D7BB360B83D0C101FDE1F0D4EF2D46B0256939FFC40195AD174B68F862843D618E9882DE91EA181F12DC65F277DA0A8292D678025BDC529A238F275856E19B8A8CB6FFE4486A10AD6FD322E454D4C34A3D484D10D3D22DD252AA2E23A4D2A009DE7E1F40140BC62EEA811D1436578D5D36BA134E7A4BB6432EEF4D75B9BA075C7CA155995E83739C882FE0811DB9E07AA26BD9825E9451DA3F22F651EC92C13D89FFF6780131225366EB951959B2959DFF6311E5CA059FDE8ACB28FBFD5F64A3A5274B107419B4CFE467872420216A52811AEE7875DEB01AD3A4F584FC4AF9E31D9C645C699A5BEC9638CEEC7E89FB853110D6CC2D647F8567AF63F0AB41F580934F304F89E101D20A5DECC35F9020B1C4E5B6567787A8593A2A40A2025263A6473898A9DB2C4C5CED0F7F9FF0A152D3199C5D6ED05182021313A4142494B4D4F52535A616578AEBFC6F5FA0000000000000000000000000000000000000D1F273E"
    x = ML_DSA(ML_DSA_PARAMETER_SET.ML_DSA_44)
    sk = bytearray.fromhex("42D25F80F14F915DDA55C441E9AE33CFB7FC1CBCFABB578B93B45AFAD65F887223F61354AEA9C590B30C452A7B926E00F49CAD3F13241CD5A42EBD41161B895EBFFF9232CD0A300033246E358BFEBE6656D2A6F465FC4E49D4976302FF87F4E747EFCFD316D7BEDC5888163972A30ED27279F41A6CDB97BF38460A3B2610436FE11224029870533621548480DB402E1C904912110958C204004586180410CC4824DA266210B860618061C2948D2447505C42458412660825450A49725B862900474602B48502B6600BB5419C860808A2849B184901A19000202EE0204A982452948630D0948999A05014A2691024450B318D59384804384153048808010418354111000992048904434C10032452A68C929668DB2226D2A80114416C5CC690C0300863966411B12019885023436ADB38100A17891C332412220A498284591032E22488023824D8A62C922672211661109970929611E1B86D1C25320040108936022346298B9821A1C26904A78C101608C196104BB6640131624020620B416613458453880552069012228949042D63060EDA166D94420D43B80590C004901204A0182919462D8BB62D88C0250C969094160E1C94480298288B38921B290A118928D8324D81A0511B260C600650D1A83001126941B210411429124826C4860913422409058510C5459B002402426588A24813B46C8A302A8CA864020308641031D1122CC9C8840C3420D1968C90C020DC92041BC64502474C19138114024ED83285182086023524083305184281644606D9167114B22D62320AD128885A92300C2968DA308EA1984891C08D23A34422085094B41054464643204CD9060A81444264B0810942529C242A8890899C486D5CC0115310458BC86C5A268E18154E02465214189210124C01046DA1C20450444C14A31098C4858A38901B19029040920A0949138804C2362E1B291059984C098585DCA63104A9505C36125A82808C18801AB421232372DB244519A609C4082414A870A4220D0424651445909C804C62B448028171901261210848A308200A8064D9A42C89144E60188A4C264EA12842C81269D3320A9B068190C6602003200AA38120380DC9C860DBA611C2888194C68501A7404AA21011847164306C8B206064B8919186011B166211A5402446524202669902426340258BB605CA848D5AA0201327520216610CB380C99224A1080962A481C4240EA0806504104598A82950989104136D82208D9090109C4051142312C59BCAE3A64980141D561DA0EF260A5DFB56040E9C03CA9694E7DA85ED368A377D16D7675F59C59DED209C7DB4E96EB24B7777399EA0249DD3B9C951DBE86D77C6BF376193035EF1EC5993503E6C8A4DD87DA8A68F0B0B536502E5A53DCE57644330FF942BCB392A4E8061982A6D48DF6F537BDFDABFCB2F9036DF7844481248757993ECA397645E2F9FCCDE5E66213D6109FEBB59A45D3BD5D6D3A6AEFCE4C0A9D940C855CF5AD44AB6D9132B0CD0AAF2D99FB668B6C10B4132E9FF232515BD1AE4DA2B6F1CEFC3FF8D41982EE8A66D50FC303CDC61C010F87B02AB79051912F82403CDEDC73FCDCD5D6EBEC7EDAEA1E3B85F382FF247B8C3E7BB1D9EC2658C03926CCCA61B999547FBDB3007682957D6438638211EF34D24831A5DD74A9AC4708A19C11A191023A903563D776944C15FF025E362E9114F3BFF32B4D91DD162BE71E6D71EAC39F294C574D6DE3C3F348106E1B97292BDBDAD7F04759EA366A01F1CB8810E399DAE11DDBF53FDC67F2EC3E1FCF208B91E8979DB1C3915FC529EB5BF98A2FDA3B50F6C34DF033E33F07CA374D9D460A0351D4D9E5CEEB169F176EB25E30BD40B54DABA066FB9DCDD02CE86E5EF445BA5931115CF20AA4062FF2227BE2123E3008AC0CDD3C3C5EFAEE14B2A8A03C502D74073277ACC2F77EA64A1963BFC24DE56FA55A8957ECE1FA8355CA2086146C2A64A5606A7C93D460D145E45B2BEC7CAE4FF5B8EDB96CF7F60DB47EDCC010561B9073C9623A4C14334643A4A377FB2D892DB5E5DE2531BC3CC716C4A04A93E4EFEAA07BAB1E1B82AF3E6A65AC1E4D20937A4031BD2E4F5C95FFAC0CAA595E497A049754AFF28D9F44FBF73CADA7BE230D0C7144B6C13BE1D56B490D5549A6C58113CCA60391C4062D56257DC54BF1C1C00F2D3655F96B7466660B7F761243A0CBC260472C5439B07F8A4316CC227AEC12B0BF0D7C3CBEBB6F861C6B6C1FDDF258CA80921F570278AB4CAC743D171566560CB9D962D69F7A5954E563E319973CD1801BFC4B5C7601A544E7ABEE1B223B08A525E82B0F45D39400F14BF030F7D8DC3A2E15BE43F087DCCBCA3CE4132ADECE0AD28E9076206C777F648B26681647D4225B0093D39E0C4D802E1E6A82D646961BE32BA5427F3BFA1677A4C8DD52102EC6C732A9F4FE56FA856B17EFF1F95C430E7798C418F192A131B8AAF6EF98F3686B20929D03CA1B7309F471682CC01D13596D628F49B626EDA90B9C5E19C5D34FD888E045DAB9E96B1402D873F1890AFB5978AF7BD872147602157F5F73195668CF465F4CEC2C683C7EDDFB78D4138C6E91CAFBAF34333E2FA63B4EAE4ACF42556EA3EB25C0A05915D9C8FA2AABCCD2B4F4C9AB2B288D09031FA66965F81906D3CA447EB297E940DC7B4559DB73826538A86475E03748453E7A4DD7F2E69DE633970217CCABBD0FFDB71935419EB7B07835E30CD6CC56F9761133CD49C63AFA8D6DD2D98453AB2CF54F8006EB8F21DFB8123F56E6319E12843880226DC887276782E6439027BC506576E33DE561966248C98F4F61EFDA02A98FB4B2FB9E90E95C718F9FF1C8ECA1240B447FFEAD5A9C1B205ACAC96E79132603753C991A66C36F65EC7367BBA5A7AAC4660A99C736A53FA047C7FBF495FD0D26252C14F28BE375F519F52A826E9D2DDEE8647DC6D1B5049A08876B945958AB746C41DF923B2725849F21C961DDEA6CD05A4E2A035317DD713BE6767521BC6D2DABBFD7F0A388E12876A076931ADE9D6E86B5BA5A38F91FBA1837D40FA8FF9558F5D28EA59CD050F2B891EA0E682EA17EC4B02152FC25B32041FF558455DC2AAED45F31448565152142A58855608DB49F1C0C355410BDC1838D74ECB69D2B365C64B3AF293511D6F39AD1DBC719DE9D4192F495D9153386B3C0C86C1D341482B6A0311A3CC2044CEFAE324E806E11219D04A28CF9FC06FDD24E90AB5E95A78F3110DBBED69CBF800AA2ED8D2AC44615AA61CEAF907119B1B61E457836F1C93CFABFB85ED16DA776B641732831CAA5C0EFF048A702F03E8414C34B95846CE9E80A774E6B20493B78CFE686CAF8CC08259FE4AC3B59E3A3D1A6203C3DA4C37F812EDBD5D89A297E96893F0DBDCAA5747166EBB888401EAA5DBEF9EDD86FE446859DEF6D268DCD3A839FCD1397CDEE756802BC59D5859A90054A90414EC51A36705EB8366576CE18515373D1350AE72161FDC948A602D1D27BCAB7B7B212BBA31014BA0E229B17F8D875356A93B2D98AF49BD9C0587D3AFA0DE480721B277B51CE0DFA91FECA620EEBDEF2786241DD2DA522B1A0396E7E9997BA59E0D686FD82D9B334865370E9B326A280670A945BD94328872")
    M = bytearray.fromhex("97F51A22032B01133CE41F0DFE106A27E71F0F0EB7BF65F83ACB32595E09291AEFE8AC96FA71B72024AC08BFB9BC7685222F915360332A438B1494BA4C25BF44A3D9CA75968D5779727042E202F10DCE857E7F1D4ECDF4B95D422451EA2990668E0AB0C78BFC04A24DE02054ED8785AF667FE3DD8C4D4F54A055719A2FA55992C4306988A1734E695B0B6B9D21940FCEDC54F644BB5597F893523AD96560AEB97E42E9FD5662035DC39E322346E2A6DB2FD6FADD5ED7D4AE2DC0EAA5D112078E2FB280C86F3FA5D631551B8F03C4B87DF70CEB6DEEDD6BFE0B583CFB3835B3DF2E36E7FE609EE71B44E9BBCAD5DF0669BB23DA84F136C517B1E167565BE9BFED20F16F0A2E74A0D291DDA3B4F41CDF72AF97E4F822D3D09E401673017078F8E89DB0E7B552B501A01BFD58C1D4062D24E2D7CF54D15C9D07A7C1BF3014BCD0E99F78BA2241C24A7EEBB654C0DB775F004688BD4062986057D228779C33ED566FBE3439340674AC9F1831EC32B370301E5EF31D6B2B8E1ED8ADC196ED6262AFD7E808300C96BDF463F4E9CE80700E186916D9FFE3C53F78EE40CFF2FBD7A089E7B15C40CCD947F85DD6E2AAA47C5FA8A0BC6E8EEB4A613429D409538F1BCB469E8D4BDF19AED4D7A5C54944FA684DF7945F0EC61E3F16329176EFA1B0ECBEA61BDC13F174F307AE838CCE027DF3AB1976BA404DC2E723B27FC0D3215D586473C7C638A581C3B2D4ACD0AE41F296F365974DF91560856D548195B527C8B47E31CEC098705942666FCFA0D32F3BA54734E79CD6DC8A3234603791E7E833827580FFE9E63ACBDA026D29834794E6A4E5697DE8A93D347E1BB4FA644A5BB090F31734B9D4200EC51D90DA0A5AA5E72FC581EC98782699A939D40AF5FFE96ADC7884282EC3AB26D202F60F43E76E5225A9FA4DB53828141C46F865FAF210BB2CD4C179ADCA9129123724C18C43E0A19FCFFC06BB163F9EF231F3C0EDBE5DF6C3825223890E2222B0B663F4D61B450F06E52358E9D43E7FF74B88CFEC41E0762BFBDCD252E687C327E6DAFA9536EA7A01DF01CD3589F29F55A50A10D14A088AB1F92BC09547EF07B258E1DC739324025C5919F5CC916F57BC721942EE3A1B09C24E8EBA3946D31BD5CD5FA4E0AE116EE7F94BED53CBD83FB364076962C4D512FDC28B85020CFCA7466DC1A4D123BCC3DB7C06C44C19CB4ED391C635EE1989967230C89C72EDEBEEBE97061F19ACD17A9AF583EC5A4742C65EFD72EEFBBA3F4C8CDB51A29E56B95E68610C8FDF2A4B467FC2F02D661571C4D366F32B4B544FCA27E64A65F2503C8B23EA01CB0B152C5229BE424A846633D74044F3DAE1DC486A2D17A50C7D7504C20C74949AECB108C641D50794BF7CE2CCF2C7DBF71249FFB784EE7D14DC6E27315301C76633269E1B3C0624E193CD59AA2C817AA4A657C4D4DBC7C08BCD44CC65B79B6118270E4E6D6C814FD71EDA7E447A4B58A8D3DECCB41AEF7481930A9D8BDD42BC1212D3F6852A4E83730CDEC3504854956BCFA9A873AD74EC1D9378BCEFF55BB5E12BC79910B628527B527A29070D08F94FFA92E79324E7D9ABE4ADAE7CCAD6EE35E5D05841A490FEB73CCC5B871FD0CB41F486C6E3919BB283083DA0B5E08E48AD0148D7D84AEDD6C075792ED66BE2E884628E0A1283EF7EBDA8A22F7A5173306BA2C66908552DCFFF9949D210595B2638B8F12810F9EA736B512D0519ED6F0A48898832911BA1768B9E04FDF65BD0EBAEBC1DEA5BBCBAF3D45784A9CCB86E0496402DE04409E256A24CE5CAEDBFCBF0FBF9BD87F1064A766ACC3B737144C37069F1BDC24BCBE46B440EF0A53225C010CBF5ED8F28D7F6530279AC2975266493F218F0ADD096E5E888E65FE7594CEF16F5B19AD6D7B588599F8D5831B36D51A3F64AF2223CB5C166CCC545B03195E15BAA5F96C7CA5BDEE43A2C6292FCB2AECE96907D3BA79A768C786532B69AC385021F55E3623BE83474869ABCB2413ACBFE7CDF74B69700B08DC1D1B0FFD0647FF7DEA4CCC8B02AAD0B47143B5827385E2865021B19BB64A7EC1D938CE9F37C89C1F2E4EBA062300097F92F1B3EEDCE214EBBA37C592671DCCA442FF9B0C2A63A63532826488719CCE15B428B972EEB1B17434F902EE0DCEA192D72B92F125BDA84C64A2A08E5649D4BD25C36118A093DFE5E0C0C9C2B00AD7E310BAD24659E3E915416A16BEA79234FEBBB2F8D5B1C24DA971ECD51ED2E9A67B5158208B4890701E9912EAFE4D41D2B5DF9CBC5686393B31462AE6C9F282382C5854007A58049B68197F0EECF383D458A6D7910B060EDF61C2789FE408899DA80FDE8211AA899D70A7B255659B0DB9D60EEF53902A380ADA75AAF3F575432A7EE4A9EABD69E3380A67CB4300E9551CC66E153723087241EA8BEC04E284053BFAC34EBAB7C417EB46125C027C2286C67A9D87FAB13DEDBD9F51BEC545295A567A376597AFDFAA4E68C67510C611939951312E3CEA8F63505AEE8A520280B1BB3312240FBBE7F7A8CA627A249E48AC29A3B15606D48D789E47218FA77874A0E2EB0369624B475AA737F2CA532DAA81EA9602C6B363ACBE9C746F57169F3F9B84C5A7DF1023323C7A74B9A39329FD0D9E382EE70409668ACA239C9477B1CF60DB85E4502B48BA097D16C029EE66E23918D718E6001B217915C317DA2CAF434A9EA80A755315E4A72E2EF235728C5DD1FDC943BB0C6E18E60B37660FEFD8286F4C42A63C38DFF26C92155418F12CB08BD2F7B2551E8F8D44E44355457276BC7237F352230820C9A01E624A99A2FD29508CE886AC5A6062AE75AE6D028000DEDCBEF7062A7D4D6469940CB5712E02F35145D55651436B794E1DDF606C8A6DBCC3E3789C964E7F25E339DA17C3AE707DD61AF7704CD4B2454B9D5499A320AE33ABC063F1ABD91E48C6223B0398B70692B772911ACE198D37E51475A49735482E4D62CEDA4127F07735B599CA0CA769B141EBDEFB4EEB967AAAA529AC40440E5FEC47AAF278588E867DEFF6548427DD0EC0C5F895853465F8653722DFBE6E572C1A2DF1E9A62A873A81643FB4D3FBA1CD74D81AA760287DDE21512CFF931FEAAD94DA5035F551E6DB6D58CE031297498226C5EF991BEC067A53E74B8D05E4934F67424C2D7DD893647126837692D1C57CEE22D4365F41EFD107DE1E88B65801E0DF50D4D80437A50AFC3EEAFBBD1E48626001D507D562A04C1A406522D38F935C224084EB44257EC33AA998FF8E0A216D00E20859A43421543C190D82FAEFA4953E7905DE7B5954786B893C06C6DC6517D350028814D1C5382F0034989DDA4C76A06FDBE321F4CD136A2D3B796C406470B1AB6D375654F51A6C27D3486CCE9596F2A8572B5D16B3308768DD19EC315FF248A15733714F1EF79B2909E525547C473727AACC42AD1218DEDE76755C9033661D089CE905DCBEAD6499D86F3F921F0DDE39AA2F977CFAD58A6D103FEC83916398397744525A70E14742393D829C85EF1E52F8EDF3DBAF844CEF3386BE05EF9DD75B0BB5812D60C717ADFB46F137C4BDE3CE35CC1168CE93EF0861B311988F42893A75474A69BD442F0A46C26F9E9CAEA2551F4D4878C84CA2561F3E718FD16E606AD59DE67703031B7E44E9A560EA0E46E342F2F6FFAD6EC85BBE5D7CC8C263F3FC33599CD381F548163CE5E7909860A39C0733F3D55A93B47261686C5B2948642C8A3DD19DAA4E2746C8519361E129C42AA8961126807E2A04E73721A93C1077D047C8CA5C8B5C32286A845384A8ABB98311A86B9118BBE5449A5CE9DC7681CB1BE63C0D9ABCD5D3043739D275C2C461D113983B072C5E0C555387326E5069524CFA16490A8CDD2B5CBF87FF250138CBCCCB4A45C8DEC5323F369A67E832829C265EE3BE9E812D1B696119CC5E9D42EFCB6F64F0FC9FB130A8A4DA27A8369C668BE68C67F1043B31BC36E58A1F6DD7196E32AE74991E72A2C6E4B2C9B2D9524EEB293A35A6B12269E3FE0F7F4278256B6E9D00FA75779FB62C2319236E1F2FBBA627F234C945A67F2D13FC28C49ED5E00810D8E2950866ED6E037B5D204F8DD026D41E18583D7C478F95F2EC64FDC997704962EBEF568FB4305A62459D3615200051169E3646297B0CC84914CCA747D0591883457F8E214D62546E81A8891FC8BABF93ACCE22B0038EE26A1093F218AEDC1ADEAD0EDFDF940DE4B0F659B85D76E8DD06D55623EB27C582155F123F22234AB83A05FFF8A5C184E9D0A94A7595A4318C5FC61553671620CEA5A491648DDE9E0B6BEF5C8EF338932C28BD3A0BF67B36B6B3901DB03EB6978694F33148EDBD970AB540E0CC5AE52C6D764409FE9CB5C1E6FD8F1214E9435C5CABA7742FA6196032ABC6C1B8522435D5B4F7038B03432E1912E7525DE042D1870942F080CAE16479CF1D41CACED4CE4FECF267BACA559F9C383F011A933F4FFD81909D107412D81CB1DDD0A2EF565823F1E59D30305317966364A3930E2647AFC021112708C0357A32A81DE1FBF300DBD20F30DAEF101EA2B795D0A99D0AC4CFBFDCA5F0322A2322C07C405F05CF3C441E309DC2E5F78C661153413BE305E6730713A138372F1C7FC226D26B763005F8D1C3BF738DCBE36104ED1F5E99F559A2E7C69F1BC80E07CDB41B8ED958814320B1EB314CA8DE39963F79464EECD09B50F03AFCC960B7D403105851B75212DA4B2C0C2F255659EDD4900FC3AC11282605D2E0FC32DC7F3CD100879686A2D995F315576712D66E31FC6DD9489D98E48AA6DEF490F815EFA2931F059388464BADD89D6C809BCEF50A63D902128F124BD6A40FDCD240A2335FA5E33607E0D20AFE80586AD97F888A73B145332B758585D926E6758344DBF64376DC192642A64FA6F487A804EB62CD199311BE46E5AA3BBF0978BE2088FF86385D564C3CA22D956F8C28D5A1349F51D5070E82CB045399B318BB43E815DBDFCA38ECA44D47D41815DCC29A8F6D446A5D60C3FC68C9BF1501938400CA43722226A832F5AEFCB2A903674C7A29652D472975875A37F287FD2E9B90FFF0E78F6256EBFFACA46DEFD4BB0BFEE0C6EDB0A28374F849A5C90E2654E7639ED16DA502580357DA07A0CC11CF3D234618DCE4923A725DA5E9E775BEC6074D708FBF11DE4217CDAB7FEB14E11AD2211B87D42DA257E35DE34BE72A25BED7C52C81D6F3F048AB1A467F4C758855A98D140D24868B23DF4773BF5A895C6E4CE7E5637A8AA7F63E301E6F5171AF570D3DC543886296CD28971C8EEA2E88B979A7F0EBDC85936ED09C7FBB53B3CAFBD65DEDD332D6064DC3C1F90DF98882ADFB62132C6D75B4EB1108198EB06A8F119506076CDC741B9CC46E518170B466FA2B2025D2D56FF1DDCABA575E62CAAC254379B26072ADCE1134E88C6F537F9578568C595C9FC29B47668A1A9A95508540DDB4F1162CCD86847CB5A560B76857E544ECBEF81B79DA448FDF3DF9224AD6EA5933C7AB54EA65158474D67A071B2694834CD56C4ADE849550560081E30AF9532FBC7BDE0CDB322A58F9C6901F3AAA806111042B9DF696D511D4869704BE1F4B14F5A4B1AB97B587787362D1A39679E6ED054FF2560E48D46E2765B262AA9DBBDB7A3689218795B1135A29E6DB04FC7796F9319279EAC54B8ED6493148C8E1925A4DD6A01E00E02EA7C9DD1B49C7BAA768BE8B443CE809A21A449A01B64D8AE07573BE85AC5536123D6E8A739CEF8018E7FF7EC3B9570618C3830544132D9D324D7A0AD9E09296D77234AB4300DD351F98AD2F437FC86A704D9F28433CB856E8B18B50C20F18B61732FE9C13D753A7FBC631FC6A064ECD9E3C09F2A6A9C9D61E5872A6B8C8FB51851735823D66A68A3035D20D02C6AF6B583419BD50ADDD4CB53BF2BA5193EDCDD344C31971A701A7F96AA073F68F020102D43A9686CEA65820A7294F1E9FE4E0B9C89C14C7B24F92DAA08C06F60DF3EE7B015A4674A7866F698ACBB139EC487561A671EA7D7D026D1ABF4E1D2E0FE2FC58632B671556873BB31981DA1F5A4228BDBA06E8FA5C4196686F9CFBE34978EB64EB0B7C05062F788F7C36CF137ACCB7AB2156A6FB47D763DF306D44DF06B7F9D89544EC01ED5A14510220D1B020C6D5B46BF29B335180B9C71D695F1A807AA04DF6EFDA408113ADCC99F88BF1AE81388F87D549A705F0C87F956D258B16AE598E22704159565D89B5A991241A004F3442F465C8EA08D2CE3849309E0AD9475DCE128C40D2C42CF540BF4289C42901A03367FED2646C6C0A634315864BAE390823655D1BB0729C41D6DA35560346114DCF7C3C33D17AC31B2E3CB37F05F3DF760555CFE576D12C6FABD05D37879A3726C22B8A1B144E5DF34AD3ECDCE248122401BCE04A6CD369499750823F7E0DFF1B09A5B72827E132F5A03")
    ctx = bytearray.fromhex("")
    rnd = bytearray.fromhex("31CFA3107E691B2BA6957F5DED6D2CD9BA9D5794DD897C2CA2484A8021E9E36A")
    print(x.SignGivenRandom(sk, M, ctx, rnd).hex())
    







        
