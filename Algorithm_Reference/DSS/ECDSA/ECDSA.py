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
        #TODO
        
