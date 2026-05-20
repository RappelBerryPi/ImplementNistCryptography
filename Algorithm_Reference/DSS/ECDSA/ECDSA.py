import sys
import os
import math

sys.path.append("../../")

import ECDH.ECUtil
from cryptography.hazmat.primitives import hashes

class ECDSA:

    def __init__(self, curveType: ECDH.ECUtil.ECCCurveType):
        self.curve = ECDH.ECUtil.ECCCurve(curveType)
        self.private_key = ECDH.ECUtil.ECPrivateKey(self.curve)
        self.public_key = ECDH.ECUtil.ECPublicKey(self.curve, self.private_key)

    def sign(self, message: bytes, hashAlgorithm: hashes.HashAlgorithm):
        #1
        hash = hashes.Hash(hashAlgorithm)
        hash.update(message)
        H = hash.finalize()
        print(self.curve.n.bit_length(), len(H))

        #2
        #2.a.
        if (self.curve.n.bit_length() //8 >= len(H)):
            E = H
        else:
            E_len = math.log2(self.curve.n)
            E_len_2 = self.curve.n.bit_length()
            E_len = math.ceil(E_len)
            E_len = E_len // 8
            E = H[0:E_len]
        
        #2.b.
        e = int.from_bytes(E)
        
        #11 here because do while does not exist in python
        r = 0
        s = 0
        while (r == 0 and s == 0):
            #3
            #references section 6.3, for which I am using non-deterministic, for which I am using Appendix A.3.1
            k = self.GenerateRandomIntegerWithExtraBits(64)

            #4
            k_inverse = self.ComputeInverseK(k)

            #5
            R = ECDH.ECUtil.MultiplyPoint(self.curve.G, k, self.curve.a, self.curve.p)

            #6 & 7
            r_1 = R.x

            #8 
            r = r_1 % self.curve.n

            #9
            s = (k_inverse * (e + r * self.private_key.d)) % self.curve.n

            #10
            k = 0
            k_inverse = 0
        
        return r,s
    
    def verify(self, message: bytes, hashAlgorithm: hashes.HashAlgorithm, r: int, s: int):
        #TODO: validate according to section 6.2.2 before "setp 1"

        #1
        if (not(1 <= r and r < self.curve.n)) {
            return False
        }
        if (not(1 <= s and s < self.curve.n)) {
            return False
        }
        #TODO: start here and finish
    
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
        #1
        if (a <= 0 or z <= 0 or a <= z):
            raise ValueError("invalid input into ComputeInverse")
        
        #2
        i = a
        j = z
        y_2 = 0
        y_1 = 1

        #7 here because there's no do while
        while (j > 0):
            #3
            quotient = i // j

            #4
            remainder = i - (j * quotient)

            #5
            y = y_2 - (y_1 * quotient)

            #6
            i = j
            j = remainder
            y_2 = y_1
            y_1 = y
        
        #8
        if (i != 1):
            raise ValueError("Error computing Euclidian Algorithm")
        
        #9
        return y_2 % a

class TestECDSA(ECDSA):

    def setK(self, k: int):
        self.k = k

    def GenerateRandomIntegerWithExtraBits(self, t: int):
        return self.k

if __name__ == "__main__":

      # "tgId": 11,
      # "testType": "AFT",
      # "curve": "P-256",
      # "hashAlg": "SHA2-224",
      # "d": "229FBEDCDDAEB3DB578FEBA286F44523B40E7A284974F94B6092F5995ED91105",
      # "qx": "62C9B36DE068167F48FBBD907B556CEFB7D058AE52A13D09AAE8D218DC1EE4C1",
      # "qy": "FBCB18F98DC509003BA24DA51DB1F70803EEB985B7CA4703662C909B74987983",
      # "componentTest": false,
      # "tests": [
      #   {
      #     "k": "082B667C79FC46CA2D1E12DD1CB99D00F2A1526B81463B0E8AB0F1EC7C842548",
      #     "tcId": 101,
      #     "deferred": false,
      #     "message": "1AD196DDF2A1B329E7C095EB44E4543B7E56D438FEE8C9DA96D005D54C877CBF1B87D33CEBB08A2E6D8A1EB4F037EF514893F6DB730CE1EE0D818E7DCF21B30574862334359DCE74314745E0D7D65C244DD5F7008DF0453EBC09D9BA25BC76B36AF58A4C5B3D273F9384CCB84A9DF8E63BB43946D51EFBFFD27E725DDD62F8FE",
      #     "r": "95569F25F7710D3FCC3148FAE0F86141A11487DA0F2EF1A14245CBF5900B006B",
      #     "s": "F21AD03D8110BDE4B59B8D181F436913C808CE9F9041056DF86E779BCFA80DE6"

      ecdsa = TestECDSA(ECDH.ECUtil.ECCCurveType.P_256)
      ecdsa.private_key.d = int.from_bytes(bytes.fromhex("229FBEDCDDAEB3DB578FEBA286F44523B40E7A284974F94B6092F5995ED91105"))
      ecdsa.public_key.Q.x = int.from_bytes(bytes.fromhex("62C9B36DE068167F48FBBD907B556CEFB7D058AE52A13D09AAE8D218DC1EE4C1"))
      ecdsa.public_key.Q.y = int.from_bytes(bytes.fromhex("FBCB18F98DC509003BA24DA51DB1F70803EEB985B7CA4703662C909B74987983"))

      ecdsa.setK(int.from_bytes(bytes.fromhex("082B667C79FC46CA2D1E12DD1CB99D00F2A1526B81463B0E8AB0F1EC7C842548")))
      message = bytes.fromhex("1AD196DDF2A1B329E7C095EB44E4543B7E56D438FEE8C9DA96D005D54C877CBF1B87D33CEBB08A2E6D8A1EB4F037EF514893F6DB730CE1EE0D818E7DCF21B30574862334359DCE74314745E0D7D65C244DD5F7008DF0453EBC09D9BA25BC76B36AF58A4C5B3D273F9384CCB84A9DF8E63BB43946D51EFBFFD27E725DDD62F8FE")
      r, s = ecdsa.sign(message, hashes.SHA224())
      print(r.to_bytes(32).hex())
      print(s.to_bytes(32).hex())