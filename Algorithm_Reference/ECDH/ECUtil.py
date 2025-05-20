from enum import Enum
import math
from os import urandom
import sys
sys.path.append("../")
import AES.Utils

class ECCCurveType(Enum):
    P_256 = 1
    NISTP256 = 2
    SECP256R1 = 3

    P_384 = 4
    NISTP384 = 5
    SECP384R1 = 6

    P_521 = 7
    NISTP521 = 8
    SECP521R1 = 9

    BRAINPOOL256R1 = 10
    BRAINPOOL384R1 = 11
    BRAINPOOL512R1 = 12

ECCCurves = {
    # (p, a, b, Gx, Gy, q, h)    
    ECCCurveType.P_256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                         -3,
                         0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                         0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                         None,
                         0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                         1),
    ECCCurveType.P_384: (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
                         -3,
                         0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
                         0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
                         0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
                         None,
                         0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
                         1),
    ECCCurveType.P_521: (0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                         -3,
                         0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
                         0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                         0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
                         None,
                         0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
                         1),
    ECCCurveType.BRAINPOOL256R1: (0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
                                  0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
                                  0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
                                  0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
                                  0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997,
                                  0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
                                  1),
    ECCCurveType.BRAINPOOL384R1: (0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
                                  0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
                                  0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11,
                                  0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
                                  0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315,
                                  0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565,
                                  1),
    ECCCurveType.BRAINPOOL512R1: (0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
                                  0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
                                  0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723,
                                  0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
                                  0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892,
                                  0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069,
                                  1)
}



class ECCPoint:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y
        self.is_point_at_infinity = False
    
    def isInverse(self, other):
        if (self.x == other.x and self.y == -(other.y)):
            return True
        else:
            return False

    def equals(self, other):
        if (self.x == other.x and self.y == other.y):
            return True
        else:
            return False

class ECCCurve:
    def __init__(self, curveName: ECCCurveType):
        curveType = curveName
        if (curveName == ECCCurveType.NISTP256 or 
            curveName == ECCCurveType.P_256    or
            curveName == ECCCurveType.SECP256R1):
            curveType = ECCCurveType.P_256
        elif (curveName == ECCCurveType.NISTP384 or 
              curveName == ECCCurveType.P_384    or
              curveName == ECCCurveType.SECP384R1):
            curveType = ECCCurveType.P_384
        elif (curveName == ECCCurveType.NISTP521 or 
              curveName == ECCCurveType.P_521    or
              curveName == ECCCurveType.SECP521R1):
            curveType = ECCCurveType.P_521
        self.p: int = ECCCurves[curveType][0]
        self.a: int = ECCCurves[curveType][1]
        self.b: int = ECCCurves[curveType][2]
        self.G: ECCPoint = ECCPoint(ECCCurves[curveType][3],ECCCurves[curveType][4])
        self.q: int = ECCCurves[curveType][5]
        self.n: int = ECCCurves[curveType][6]
        self.h: int = ECCCurves[curveType][7]
    
    # D.1.1.1
    def pointIsOnCurve(self, point: ECCPoint):
        y_side = (point.y ** 2) % self.p
        x_side = ((point.x ** 3) + (self.a * point.x) + self.b) % self.p
        return x_side == y_side
    

class ECPrivateKey:
    def __init__(self, curve: ECCCurve):
        self.curve = curve
        L = math.floor((self.curve.n.bit_length() + 64) / 8) # converted to bytes 
        c_bytestr = urandom(L)
        c = int.from_bytes(c_bytestr, byteorder="big")
        self.d = (c % (self.curve.n - 1)) + 1

class ECPublicKey:
    def __init__(self, curve: ECCCurve, privateKey: ECPrivateKey):
        self.curve = curve
        self.Q =  MultiplyPoint(curve.G, privateKey.d, curve.a, curve.p)

# taken from tinyec
# recursive function, essentially using modulus reductions to perform this computation.
# another way to compute this (which I will probably be using) is fermat's little theorem.
## def egcd(number1: int, number2: int):
##     if number1 == 0:
##         return number2, 0, 1
##     else:
##         g, y, x = egcd(number2 % number1, number1)
##         return g, x - (number2 // number1) * y, y
## 
## # taken from tinyec
## def mod_inv(number: int, modulus: int):
##     if number < 0:
##         return modulus - mod_inv(-number, modulus)
##     g, x, y = egcd(number, modulus)
##     if g != 1:
##         raise ArithmeticError("Modular inverse does not exist")
##     else:
##         return x % modulus

# fermat's little theorem says (number**(modulus-1)) % modulus = 1
# since (number * mod_inv(number)) == 1
# we can expand this slightly and do mod_inv = (number**(modulus-2)) % modulus
#
# we take advantage of the fact that:
#     x ** y = x * (x ** (y-1))
def mod_inv(number: int, modulus: int):
    return pow(number, modulus - 2, modulus)

def DoublePoint(point1: ECCPoint, a: int, p: int):
    slope = (3 * point1.x**2 + a) * mod_inv(2 * point1.y, p)
    x_3 = (slope **2 - (2 * point1.x )) % p
    y_3 = (slope * (point1.x - x_3) - point1.y) % p
    return ECCPoint(x_3, y_3)

# For Weierstrauss Curves (P-* curves)
def AddPoints(point1: ECCPoint, point2: ECCPoint, a: int = 0, p: int = 0):
    if (point1.isInverse(point2)):
        return_point = ECCPoint(0, 0)
        return_point.is_point_at_infinity = True
    if (point1.equals(point2)):
        return DoublePoint(point1, a, p)
    if (point1.is_point_at_infinity):
        return point2
    if (point2.is_point_at_infinity):
        return point1
    slope = (point2.y - point1.y) * mod_inv(point2.x - point1.x, p)
    x_3 = (slope**2 - point1.x - point2.x) % p
    y_3 = (slope * (point1.x - x_3) - point1.y) % p
    return ECCPoint(x_3, y_3)

def MultiplyPoint(point1: ECCPoint, d: int, a: int, p: int):
    returnPoint = ECCPoint(0, 0)
    returnPoint.is_point_at_infinity = True
    doublingPoint = ECCPoint(point1.x, point1.y)
    i = 1
    while i < d: 
        if (d & i):
            returnPoint = AddPoints(doublingPoint, returnPoint, a, p)
        doublingPoint = DoublePoint(doublingPoint, a, p)
        i = i << 1
    return returnPoint 

if __name__ == "__main__":
    #p1 = ECCPoint(-1, 2)
    #p2 = ECCPoint(0, 0)
    #p3 = AddPoints(p1, p2)


    #NIST SP 800-186 P-256 Gx & Gy
    p1_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    p1_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    a = -3
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

    from cryptography.hazmat.primitives.asymmetric import ec
    # Generate a private key for use in the exchange.
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    d = server_private_key.private_numbers().private_value
    ## # generate public key
    ## #p1 = ECCPoint(p1_x, p1_y)
    ## #p2 = MultiplyPoint(p1, d, a, p)
    ## print(server_private_key.public_key().public_numbers().x)
    ## print(server_private_key.public_key().public_numbers().y)
    ## print(p2.x)
    ## print(p2.y)


    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though.
    peer_private_key = ec.generate_private_key(ec.SECP256R1())
    shared_key = server_private_key.exchange(ec.ECDH(), peer_private_key.public_key())

    p1 = ECCPoint(peer_private_key.public_key().public_numbers().x, peer_private_key.public_key().public_numbers().y)
    p2 = MultiplyPoint(p1, d, a, p)
    AES.Utils.printByteArray(shared_key)
    AES.Utils.printByteArray(p2.x.to_bytes(32))