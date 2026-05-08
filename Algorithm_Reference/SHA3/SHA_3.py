import sys
sys.path.append("../")
import SHA3.Keccak 
from abc import ABC, abstractmethod

class sha3_base(ABC):
    def __init__(self):
        self.sha3 = SHA3.Keccak.SHA3(1600)
    
    @abstractmethod
    def hash(self, Message: bytearray):
        pass

    @abstractmethod
    def SHAKE(self, Message: bytearray, d: int):
        pass

class sha3_224(sha3_base):
    def hash(self, Message: bytearray):
        return self.sha3.Hash(Message, 224)
    
    def SHAKE(self, Message, d):
        pass

class sha3_256(sha3_base):
    def hash(self, Message: bytearray):
        return self.sha3.Hash(Message, 256)
    def SHAKE(self, Message, d):
        pass

class sha3_384(sha3_base):
    def hash(self, Message: bytearray):
        return self.sha3.Hash(Message, 384)
    def SHAKE(self, Message, d):
        pass

class sha3_512(sha3_base):
    def hash(self, Message: bytearray):
        return self.sha3.Hash(Message, 512)
    def SHAKE(self, Message, d):
        pass

class SHAKE128(sha3_base):
    def hash(self, Message):
        pass

    def SHAKE(self, Message, d):
        return self.sha3.SHAKE(Message, 128, d)

class SHAKE256(sha3_base):
    def hash(self, Message):
        pass

    def SHAKE(self, Message, d):
        return self.sha3.SHAKE(Message, 256, d)

#copied from AES Utils.py. Ensure updates go both ways
def printByteArray(byteArray: bytearray, end = None):
    for o in byteArray:
        print("{0:02x}".format(o),end='')
    if (end == None):
        print()
    else:
        print(end, end="")

if __name__ == "__main__":
    Message = bytearray([0x01])

    sha3_instance = sha3_224()
    MessageDigest = sha3_instance.hash(Message)
    printByteArray(MessageDigest)