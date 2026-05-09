from enum import Enum
import os
sys.path.append("../")
import SHA2.SHA2
import SHA3.IncrementalSHAKE
import SHA3.SHA_3
from array import array


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

        #2
        A_hat = self.ExpandA(rho)

        #3
        s_1, s_2 = self.ExpandS(rho_prime)
        #TODO: finish (start with creating ExpandS)
    


    # Helper functions

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


#Algorithm 11
def IntegerToBytes(x: int, a: int):
    return x.to_bytes(a, "little")

def H(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE256().SHAKE(str, 8 * l)

def G(str: bytearray, l: int):
    return SHA3.SHA_3.SHAKE128().SHAKE(str, 8 * l)

#H.Init , absorb, squeeze -> shake256

#G.Init , absorb, squeeze -> shake128
