import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import NewSymmetricKey

class Cryptography:
    def getRandomNumber(length: int = 16):
        if (isinstance(length, int)):
            return secrets.SystemRandom().randbytes(length)
        else:
            raise TypeError("Length isn't type int. Found {}".format(type(length)))
    
    def generateIV(length: int):
        if (length not in algorithms.AES.key_sizes):
            raise ValueError("length must be a valid IV length: {}".format(self.aes_cipher_key_lengths))
        length = int(length / 8)
        return Cryptography.getRandomNumber(length)
    
    def exampleUsingAReadOnlyByteString():
        # declare a modifiable byte array. Assign each value the i value to prove that it's not just 0's
        # print it to show that it's not just 0.
        B = bytearray(16)
        for i in range(0,len(B)):
            B[i] = i
        print("Initial:                     {}".format(B.hex()))

        # set up a memory view, then declare a readonly memoryview to pass around. 
        # the with will ensure that the code is easy to read, and the read only memory view is unmodifiable by whomever
        # it's passed to. the memory can then be cleared after control has been passed back to the function.
        with memoryview(B) as mem:
            with mem.toreadonly() as memReadOnly:
                # CALL YOUR FUNCTIONS HERE THAT USE THIS BYTE STRING
                print("Using memReadOnly:           {}".format(memReadOnly.hex()))

            # clear the memory
            for i in range(0,len(mem)):
                mem[i] = 0x00
        
        #show that B is now clear
        print("After memoryView is cleared: {}".format(B.hex()))


if __name__ == "__main__":
    Cryptography.getRandomNumber()

    IV = Cryptography.generateIV(128)
    with NewSymmetricKey.SymmetricKey(128, IV) as key:
        cbc = modes.CBC(IV)
        aes = algorithms.AES(key)
        cipher = Cipher(aes, cbc, None)
        encryptor = cipher.encryptor()
        buf = encryptor.update(b'a secret message') + encryptor.finalize()
        print(buf)