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

    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though.
    # peer_private_key = ec.generate_private_key(ec.SECP256R1())
    # shared_key = server_private_key.exchange(ec.ECDH(), peer_private_key.public_key())


    p1 = ECCPoint(p1_x, p1_y)
    p2 = MultiplyPoint(p1, d, a, p)

    print(server_private_key.public_key().public_numbers().x)
    print(server_private_key.public_key().public_numbers().y)

    print(p2.x)
    print(p2.y)