import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Cryptography:
    def getRandomNumber(self, length: int = 16):
        if (isinstance(length, int)):
            return secrets.SystemRandom().randbytes(length)
        else:
            raise TypeError("Length isn't type int. Found {}".format(type(length)))
    
    def generateIV(self, length: int):
        if (length not in algorithms.AES.key_sizes):
            raise ValueError("length must be a valid IV length: {}".format(self.aes_cipher_key_lengths))
        length = int(length / 8)
        return self.getRandomNumber(length)
    
    def generateKey(self, length: int, V: bytes):
        U = self.generateIV(length)

        # length already checked
        length = int(length / 8)
        if (len(V) != length):
            raise ValueError("V must be the same length: {}".format(length))

        B = bytearray(length) # syntax?
        
        for i in range(0, length):
            B[i] = U[i] ^ V[i]
        # start here, finish coding.
            

if __name__ == "__main__":
    c = Cryptography()
    c.getRandomNumber()

    IV = c.generateIV(modes.CFB, 128)
    Key = c.generateIV(modes.CFB, 128)
    cbc = modes.CBC(IV)

    aes = algorithms.AES(Key)

    cipher = Cipher(aes, cbc, None)
    encryptor = cipher.encryptor()
    buf = encryptor.update(b'a secret message') + encryptor.finalize()
    print(buf)