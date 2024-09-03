from ProperCryptography import Cryptography


class NewSymmetricKey():
    def __init__(self, length: int, V: bytes):
        self._length = length
        self._V = V
    
    def __enter__(self):
        # add things to say why doing this is important. 
        # reference nist.
        # talk about how bytearrays are modifiable and need to be cleared after so a `bytes` is not enough
        # talk about read only memory views to be returned to callers.
        # discuss clearing memory
        U = Cryptography.generateIV(self._length)
        length = int(self._length / 8)
        if (len(self._V) != length):
            raise ValueError("V must be the same length: {}".format(length))

        self._B = bytearray(length)
        self._mem = memoryview(self._B)
        
        for i in range(0, length):
            self._mem[i] = U[i] ^ self._V[i]

        return self._mem.toreadonly()

    def __exit__(self, exception_type, exception_value, exception_traceback):
        for i in range(0, len(self._mem)):
            self._mem[i] = 0x00
        # print(self._B.hex()) # proof that the data is destroyed
        self._B = None
        self._mem = None
        self._length = None
        self._V = None
        print("everything destroyed") # debug

    def save(self):
        # TODO: complete with file path and key wrapping / encryption options.
        raise NotImplemented()

    
if __name__ == "__main__":
    with NewSymmetricKey(128, b"ABCDEFGhijklmnop") as key:
        print(key.hex())


# only for Generating keys
# need to update for Loading symmetric keys from a keystore.