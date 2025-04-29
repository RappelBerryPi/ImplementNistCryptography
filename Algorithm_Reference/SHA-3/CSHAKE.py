import Keccak
import math

class cShake:
    def __init__(self):
        self.sha3 = Keccak.SHA3(1600)
    
    def cSHAKE128(self, X: bytearray, L: int, N: bytes, S: bytes):
        if (N == b"" and S == b""):
            return self.sha3.SHAKE(X, 128, L)
        newX = self.encodeString(N)
        newX.extend(self.encodeString(S))
        newX = self.bytepad(newX, 168)
        if (type(X) is bytearray):
            newX.extend(self.sha3.convertToBitArray(X))
        elif (type(X) is list):
            newX.extend(X)
        else:
            raise ValueError("Not sure what type X is so can't do anything with it")
        newX.append(0)
        newX.append(0)
        return self.sha3.Keccak_c(256, newX, L)

    def cSHAKE256(self, X: bytearray, L: int, N: bytes, S: bytes):
        if (N == b"" and S == b""):
            return self.sha3.SHAKE(X, 256, L)
        newX = self.encodeString(N)
        newX.extend(self.encodeString(S))
        newX = self.bytepad(newX, 136)
        if (type(X) is bytearray):
            newX.extend(self.sha3.convertToBitArray(X))
        elif (type(X) is list):
            newX.extend(X)
        else:
            raise ValueError("Not sure what type X is so can't do anything with it")
        newX.append(0)
        newX.append(0)
        return self.sha3.Keccak_c(512, newX, L)

    def KMAC128(self, K, X, L, S):
        newX = self.encodeString(K)
        newX = self.bytepad(newX, 168)
        newX.extend(self.sha3.convertToBitArray(X))
        newX.extend(self.right_encode(L))
        return self.cSHAKE128(newX, L, b"KMAC", S)
        
    def KMAC256(self, K, X, L, S):
        newX = self.encodeString(K)
        newX = self.bytepad(newX, 136)
        newX.extend(self.sha3.convertToBitArray(X))
        newX.extend(self.right_encode(L))
        return self.cSHAKE256(newX, L, b"KMAC", S)
    

    # not doing any other functions because they're too much, no one uses them, and if I choose to add them in the
    # future, I can easily
    # TupleHash
    # ParallelHash
    # XOF functions for all the above.
    # in total:
    # TupleHash[XOF][128|256] (4 functions)
    # ParallelHash[XOF][128|256] (4 functions)
    # KMACXOF[128|256] (2 functions)
    # this is 10 additional functions that I don't really need to do the work for. 

    #helper functions 

    # 2.3.1 

    def right_encode(self, x: int):
        if (x < 256):
            n = 1
        else:
            n = math.ceil(math.log(x + 1, 2) / 8)
        bytearray1 = bytearray(x.to_bytes(n, byteorder="big"))
        bytearray2 = bytearray()
        for i in range(0, n):
            bytearray2.append(bytearray1[i])
        bytearray2.append(n)
        return self.sha3.convertToBitArray(bytearray2)
    
    def left_encode(self, x: int):
        if (x < 256):
            n = 1
        else:
            n = math.ceil(math.log(x + 1, 2) / 8)
        bytearray1 = bytearray(x.to_bytes(n, byteorder="big"))
        bytearray2 = bytearray()
        bytearray2.append(n)
        for i in range(0, n):
            bytearray2.append(bytearray1[i])
        # for i in range(len(bytearray1) - 1, -1, -1):
        #     bytearray2.append(bytearray1[i])
        return self.sha3.convertToBitArray(bytearray2)

    # 2.3.2 NIST SP 800-185
    def encodeString(self, string: bytes):
        S = self.left_encode(len(string)* 8)
        S.extend(self.sha3.convertToBitArray(bytearray(string)))
        return S
    
    def bytepad(self, X: list, L: int):
        z = self.left_encode(L)
        z.extend(X)
        while (len(z) % 8 != 0):
            z.append(0)
        while ((len(z) // 8) % L != 0):
            z.extend([0, 0, 0, 0, 0, 0, 0, 0])
        return z

#copied from AES Utils.py. Ensure updates go both ways
def printByteArray(byteArray: bytearray, end = None):
    for o in byteArray:
        print("{0:02x}".format(o),end='')
    if (end == None):
        print()
    else:
        print(end, end="")

x = cShake()
message = bytearray(b'abc')
# printByteArray(x.KMAC128(message.copy(), message.copy(), 256, b""))
printByteArray(x.KMAC256(message.copy(), message.copy(), 512, b""))
# printByteArray(x.cSHAKE128(message.copy(), 256, b"KMAC", b""))
# digest = bad8c820c19c56d72b2dd4955b9bfab692d925dad1b6a65075ba60fd6f739e4a