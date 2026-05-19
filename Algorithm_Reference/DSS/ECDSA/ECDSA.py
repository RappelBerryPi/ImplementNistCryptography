import sys
import os
import math

sys.path.append(os.path.abspath("../../ECDH/"))

import ECUtil
from cryptography.hazmat.primitives import hashes

class ECDSA:

    def __init__(self, curveType: ECUtil.ECCCurveType):
        self.curve = ECUtil.ECCCurve(curveType)
        self.private_key = ECUtil.ECPrivateKey(self.curve)
        self.public_key = ECUtil.ECPublicKey(self.curve, self.private_key)

    def sign(self, message: bytes, hashAlgorithm: hashes.HashAlgorithm):
        #1
        hash = hashes.Hash(hashAlgorithm)
        hash.update(text)
        H = hash.finalize()

        #2
        #2.a.
        if (len(self.curve.n) >= len(H)):
            E = H
        else:
            E_len = math.log2(self.curve.n)
            E_len = math.ceil(E_len)
            E_len = E_len // 8
            E = H[0:E_len]
        
        #2.b.
        e = int.from_bytes(E)
        
        #3
        #references section 6.3, for which I am using non-deterministic, for which I am using Appendix A.3.1
        k = self.GenerateRandomIntegerWithExtraBits()

        #4
        k_inverse = self.ComputeInverseK(k)
        #TODO: finish
    
    # Appendix A.3.1
    def GenerateRandomIntegerWithExtraBits(self, t: int = 64):
        #1
        N = self.curve.n.bit_length()

        #2
        if (t < 64):
            raise ValueError("t must be greater than or equal to 64")
        
        #3
        sizeRequested = (math.ceil((N + t) / 8))
        bytes = os.urandom(sizeRequested)

        k = self.ConvertBytesToInteger(bytes, self.curve.n, 2**-64)

        return k

    
    #appendix A.4.1
    def ConvertBytesToInteger(X: bytes, n: int, epsilon: float):
        #1
        l = len(X) * 8

        N = 2**l

        r = N % (n - 1)

        rho = r / (n - 1)

        if (N < n):
            raise ValueError("N must be gibber than the required bits")

        #2
        if (2 * rho * (1 - rho) * (n - 1) > epsilon * N or epsilon > 2**-64):
            raise ValueError("invalid conversion check")
        
        #3
        x = int.from_bytes(X, "big")

        #4
        x = x % (n - 1)

        #5
        x = x + 1

        #6
        return x
    
    # appendix B.1
    def ComputeInverseK(self, k: int):
        return self.ComputeInverse(k, self.curve.n)
    
    def ComputeInverse(self, z: int, a: int):
        #todo: start here and finish


        
