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
        # add things to say why doing this is important. 
        # reference nist.
        # talk about how bytearrays are modifiable and need to be cleared after so a `bytes` is not enough
        # talk about read only memory views to be returned to callers.
        # discuss clearing memory
        U = self.generateIV(length)

        # length already checked
        length = int(length / 8)
        if (len(V) != length):
            raise ValueError("V must be the same length: {}".format(length))

        self.B = bytearray(length) # syntax?
        mem = memoryview(self.B)
        
        for i in range(0, length):
            mem[i] = U[i] ^ V[i]

        return mem.toreadonly()
        # start here, finish coding.
    def modifyKey(self):
        # testing
        self.B[0] = 0x00
    
    def exampleUsingAReadOnlyByteString():
        # declare a modifiable byte array. Assign each value the i value to prove that it's not just 0's
        # print it to show that it's not just 0.
        B = bytearray(16)
        for i in range(0,len(B)):
            B[i] = i
        print(B)

        # set up a memory view, then declare a readonly memoryview to pass around. 
        # the with will ensure that the code is easy to read, and the read only memory view is unmodifiable by whomever
        # it's passed to. the memory can then be cleared after control has been passed back to the function.
        with memoryview(B) as mem:
            with mem.toreadonly() as memReadOnly:
                # CALL YOUR FUNCTIONS HERE THAT USE THIS BYTE STRING
                for i in range (0, len(memReadOnly)):
                    print(hex(memReadOnly[i]), end=' ')
                print()

            # clear the memory
            for i in range(0,len(mem)):
                mem[i] = 0x00
        
        #show that B is now clear
        print(B)


if __name__ == "__main__":
    Cryptography.exampleUsingAReadOnlyByteString()
    exit(0)

    c = Cryptography()
    c.getRandomNumber()

    IV = c.generateIV(128)
    Key = c.generateKey(128, IV)
    print(Key[0])
    c.modifyKey()
    cbc = modes.CBC(IV)
    print(Key[0])

    aes = algorithms.AES(Key)

    cipher = Cipher(aes, cbc, None)
    encryptor = cipher.encryptor()
    buf = encryptor.update(b'a secret message') + encryptor.finalize()
    print(buf)