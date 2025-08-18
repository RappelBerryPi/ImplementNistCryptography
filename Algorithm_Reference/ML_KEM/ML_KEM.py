class ML_KEM:
    #4.2
    # Algorithm 3
    # copied from Keccak
    def BitsToBytes(self, bit_array: list[bool]):
        string = bytearray()
        for i in range(0, len(bit_array), 8):
            byte = bit_array[i + 0] << 0
            byte = byte | (bit_array[i + 1] << 1)
            byte = byte | (bit_array[i + 2] << 2)
            byte = byte | (bit_array[i + 3] << 3)
            byte = byte | (bit_array[i + 4] << 4)
            byte = byte | (bit_array[i + 5] << 5)
            byte = byte | (bit_array[i + 6] << 6)
            byte = byte | (bit_array[i + 7] << 7)
            string.append(byte)
        return string

    # Algorithm 4
    # copied from Keccak
    # this seems to be more efficient (without actually testing it) than real algorithm 4. Which is a valid way of
    # achieving the same result.
    def BytesToBits(self, Message: bytearray):
        bitArray = []
        for i in range(0, len(Message) * 8):
            bitArray.append(getBit(Message, i))
        return bitArray

    # Algorithm 5
    # Note here. the definition of F says that it is an array of numbers belonging to the set of all integers (bold face
    # Z) moduluo the number m (the subscript).
    # the superscript (256) is a little bit more complicated to explain. It's the Cartesian Square of all integers
    # modulo m. so this is a complete set of individual variables in the array, that are all within that boundary.
    # so when you have Z (superscript) 256, this is a set x_1, and a set x_2, and a set x_3, and a set .... x_256 that
    # are all uniquely belong to the set Z(mod m). so x_1 belongs to (∈ <- that symbol) Z(mod m) , and x_2 belongs to Z
    # (mod m), and .... so on so forth.
    # to put it into laymans terms:
    # +  This is a 256 integer array, of numbers ranging from 0 to m.
    # +  m has to be 2 to the "dth" power, and d has to be between 1 and 12. 
    def ByteEncode(self, F: list[int], d: int):
        b = list[]
        m = 2**d # TODO: check if m need to be implemented
        for i in range (0, 256):
            a = F[i]
            # this operation essentially encodes each integer into a bit array in reverse order.
            # so the number 10 in binary would be "0b1010" 
            # this would encode it so the array ends up being b = [0, 1, 0, 1]
            # same for 128, in binary it's "0b1000 0000".
            # the array would end up encoded as b = [0, 0, 0, 0, 0, 0, 0, 1]
            for j in range(0, d):
                b[i * d + j] = bool(a % 2)
                a = (a - int(b[i * d + j])) / 2
        B = self.BitsToBytes(b)
        return B

    # algorithm 6
    def ByteDecode(self, B: bytearray, d: int):
        b = self.BytesToBits(B)
        F = []
        m = 2**d
        for i in range(0, 256):
            F[i] = 0
            for j in range(0, d):
                F[i] = F[i] + (b[i * d + j] * pow(2, j, m))
        return F


# helper function for Algorithm 4
def getBit(string: bytearray, bit_number: int):
    AndFlags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00]
    byte_number = bit_number // 8
    real_bit_number = bit_number - (8 * byte_number)
    return (string[byte_number] & AndFlags[real_bit_number]) >> (real_bit_number)

