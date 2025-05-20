# see the NIST.SP.800-56Ar3.pdf in DH.py

import ECUtil
from math import ceil

class ECDH:
    def __init__(self, curveType: ECUtil.ECCCurveType):
        self.curve = ECUtil.ECCCurve(curveType)
        self.private_key = ECUtil.ECPrivateKey(self.curve)
        self.public_key = ECUtil.ECPublicKey(self.curve, self.private_key)
    
    def generateSharedSecret(self, otherPublicKey: ECUtil.ECPublicKey):
        returnPoint = ECUtil.MultiplyPoint(otherPublicKey.Q, self.private_key.d, self.curve.a, self.curve.p)
        return returnPoint.x.to_bytes(ceil(returnPoint.x.bit_length() / 8), byteorder= "big")

if __name__ == "__main__":
    A = ECDH(ECUtil.ECCCurveType.P_256)
    B = ECDH(ECUtil.ECCCurveType.P_256)

    print(A.generateSharedSecret(B.public_key))
    print(B.generateSharedSecret(A.public_key))