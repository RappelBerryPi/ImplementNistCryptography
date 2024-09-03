import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import uuid

import ProxyByteArray


class Cryptography:
    @staticmethod
    def getRandomNumber(length: int = 16):
        if (isinstance(length, int)):
            return secrets.SystemRandom().randbytes(length)
        else:
            raise TypeError("Length isn't type int. Found {}".format(type(length)))
    
    @staticmethod
    def generateRandomAesIV():
        length = int(128 / 8)
        return Cryptography.getRandomNumber(length)

    @staticmethod
    def generateAesKey(length: int, V: bytes = None):
        if (length not in algorithms.AES.key_sizes):
            raise ValueError("length must be a valid Key length: {}".format(algorithms.AES.key_sizes))
        
        length = int(length / 8)

        if ((V is not None) and (len(V) != length)):
            raise ValueError("Independent Value V must be a valid Key length: {}".format(algorithms.AES.key_sizes))

        U = Cryptography.getRandomNumber(length)
        if (V is None):
            V = uuid.uuid1().bytes
            while (len(V) != length):
                V = V + uuid.uuid1().bytes
                if (len(V) > length):
                    V = V[0:length]
        B = bytearray(length)
        for i in range(0, len(B)):
            B[i] = U[i] ^ V[i]
        return B

    @staticmethod
    def generateHMACKey(length: int, V: bytes = None):




if __name__ == "__main__":
    # print(Cryptography.getRandomNumber())

    IV = Cryptography.generateRandomAesIV()
    with ProxyByteArray.ProxyByteArray(IV) as IV2:
        Key = Cryptography.generateAesKey(256)
        with ProxyByteArray.ProxyByteArray(Key) as Key2:
            ctr = modes.CTR(IV2)
            aes = algorithms.AES(Key2)
            cipher = Cipher(aes, ctr, None)
            encryptor = cipher.encryptor()
            buf = encryptor.update(b'secret message') + encryptor.finalize()
            print(buf)

    # with NewSymmetricKey.NewSymmetricKey(128, IV) as key:
    #     cbc = modes.CBC(IV)
    #     aes = algorithms.AES(key)
    #     cipher = Cipher(aes, cbc, None)
    #     encryptor = cipher.encryptor()
    #     buf = encryptor.update(b'a secret message') + encryptor.finalize()
    #     print(buf)