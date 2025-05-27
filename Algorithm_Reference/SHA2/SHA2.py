from enum import Enum
from cryptography.hazmat.primitives import hashes

class SHA2(Enum):
    SHA2_224 = 1
    SHA2_256 = 2
    SHA2_384 = 3
    SHA2_512 = 4
    SHA2_512_224 = 5
    SHA2_512_256 = 6


class SHA2_Instance:

    _SHA2_dictionary = {
        SHA2.SHA2_224: {
            "max_message_size": 2**64,
            "block_size": 512,
            "word_size": 32,
            "message_digest_size": 224,
            "initial_hash_value" : [
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4
            ]
        },
        SHA2.SHA2_256: {
            "max_message_size": 2**64,
            "block_size": 512,
            "word_size": 32,
            "message_digest_size": 256,
            "initial_hash_value" : [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
            ]
        },
        SHA2.SHA2_384: {
            "max_message_size": 2**128,
            "block_size": 1024,
            "word_size": 64,
            "message_digest_size": 384,
            "initial_hash_value" : [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4
            ]
        },
        SHA2.SHA2_512: {
            "max_message_size": 2**128,
            "block_size": 1024,
            "word_size": 64,
            "message_digest_size": 512,
            "initial_hash_value" : [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            ]
        },
        SHA2.SHA2_512_224: {
            "max_message_size": 2**128,
            "block_size": 1024,
            "word_size": 64,
            "message_digest_size": 224,
            "initial_hash_value" : [
                0x8C3D37C819544DA2,
                0x73E1996689DCD4D6,
                0x1DFAB7AE32FF9C82,
                0x679DD514582F9FCF,
                0x0F6D2B697BD44DA8,
                0x77E36F7304C48942,
                0x3F9D85A86A1D36C8,
                0x1112E6AD91D692A1
            ]
        },
        SHA2.SHA2_512_256: {
            "max_message_size": 2**128,
            "block_size": 1024,
            "word_size": 64,
            "message_digest_size": 256,
            "initial_hash_value" : [
                0x22312194FC2BF72C,
                0x9F555FA3C84C64C2,
                0x2393B86B6F53B151,
                0x963877195940EABD,
                0x96283EE2A88EFFE3,
                0xBE5E1E2553863992,
                0x2B0199FC2C85B8AA,
                0x0EB72DDC81C52CA2
            ]
        }
    }

    # 4.2.2
    _K_256 = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # 4.2.3
    _K_512 = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]
    #helper functions 

    # add modulo word (page 8)
    def add(x: int, y: int, w: int):
        return (x + y) % (2**w)

    # shift right (page 8)
    def SHR(x: int, n: int, w: int):
        return (x>>n) % (2**w)

    # rotate right (page 8)
    def ROTR(x: int, n: int, w: int):
        return ((x >> n) | (x << (w - n))) % (2**w)

    # rotate right (page 8)
    def ROTL(x: int, n: int, w: int):
        return ((x << n) | (x >> (w - n))) % (2**w)
    
    # choose (4.2 & 4.8)
    def Ch(x: int, y: int, z: int, w: int):
        return ((x & y) ^ ((~x) & z)) % (2**w)

    # Majority (4.3 & 4.9)
    def Maj(x: int, y: int, z: int, w: int):
        return ((x & y) ^ (x & z) ^ (y & z)) % (2**w)

    # 4.4
    def SIGMA_256_0(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 2, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 13, self.word_size)
        temp3 = SHA2_Instance.ROTR(x, 22, self.word_size)
        return temp1 ^ temp2 ^ temp3
    
    # 4.5
    def SIGMA_256_1(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 6, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 11, self.word_size)
        temp3 = SHA2_Instance.ROTR(x, 25, self.word_size)
        return temp1 ^ temp2 ^ temp3
    
    # 4.6
    def sigma_256_0(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 7, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 18, self.word_size)
        temp3 = SHA2_Instance.SHR(x, 3, self.word_size)
        return temp1 ^ temp2 ^ temp3

    # 4.7
    def sigma_256_1(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 17, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 19, self.word_size)
        temp3 = SHA2_Instance.SHR(x, 10, self.word_size)
        return temp1 ^ temp2 ^ temp3


    # 4.10
    def SIGMA_512_0(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 28, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 34, self.word_size)
        temp3 = SHA2_Instance.ROTR(x, 39, self.word_size)
        return temp1 ^ temp2 ^ temp3
    
    # 4.11
    def SIGMA_512_1(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 14, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 18, self.word_size)
        temp3 = SHA2_Instance.ROTR(x, 41, self.word_size)
        return temp1 ^ temp2 ^ temp3
    
    # 4.12
    def sigma_512_0(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 1, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 8, self.word_size)
        temp3 = SHA2_Instance.SHR(x, 7, self.word_size)
        return temp1 ^ temp2 ^ temp3

    # 4.13
    def sigma_512_1(self, x: int):
        temp1 = SHA2_Instance.ROTR(x, 19, self.word_size)
        temp2 = SHA2_Instance.ROTR(x, 61, self.word_size)
        temp3 = SHA2_Instance.SHR(x, 6, self.word_size)
        return temp1 ^ temp2 ^ temp3


    def __init__(self, Sha2: SHA2) -> None:
        super().__init__()
        self.message_size = 0
        self.block_size = 0
        self.word_size = 0
        self.message_digest_size = 0
        self.initial_hash_value = []
        self.sha2 = Sha2

        self.message_size = SHA2_Instance._SHA2_dictionary[Sha2]["max_message_size"]
        self.block_size = SHA2_Instance._SHA2_dictionary[Sha2]["block_size"]
        self.word_size = SHA2_Instance._SHA2_dictionary[Sha2]["word_size"]
        self.message_digest_size = SHA2_Instance._SHA2_dictionary[Sha2]["message_digest_size"]
        self.initial_hash_value = SHA2_Instance._SHA2_dictionary[Sha2]["initial_hash_value"]


    # 5.1.1
    def padMessage_256(self, M: bytes):
        block_mod = 448
        l = len(M) * 8
        # find k such that:  l + 1 + k == 448 (mod 512)
        # this means that (l + 1 + k) mod 512 = 448
        # to do this we know what l is, and we know that we're looking for 448. so we're either going to be 448 or
        # (512*x) + 448
        # to do this, we start with l + 1 and divide by 512 and then take the ceiling of that. 
        # the answer will be 512* ciel((l + 1) / 512) + 448 - (l + 1)

        import math
        k = (512 * math.ceil((l + 1) / 512) + block_mod) - (l + 1)
        while (k > 512):
            k -= 512
        k = k - 7
        k = k // 8
        M = bytearray(M)
        M.append(0x80)
        M.extend(bytearray([0x00] * k))
        M.extend(l.to_bytes(8, "big"))
        return bytes(M)


    # 5.1.2
    # same as above, but for the bigger size
    # we could generalize this if we wanted to save room, but we're trying to copy the document
    def padMessage_512(self, M: bytes):
        block_mod = 896 

        l = len(M) * 8
        import math
        k = (1024 * math.ceil((l + 1) / 1024) + block_mod) - (l + 1)
        while (k > 1024):
            k -= 1024
        k = k - 7
        k = k // 8
        M = bytearray(M)
        M.append(0x80)
        M.extend(bytearray([0x00] * k))
        M.extend(l.to_bytes(8, "big"))
        return bytes(M)

    # 5.2.1 & 5.2.2
    # divide each block into an array of arrays of numbers based on the block size and the word size
    def ParseMessage(self, M: bytes):
        block_size_bytes = self.block_size // 8
        word_size_bytes = self.word_size // 8

        blocks = len(M) // block_size_bytes
        returnArray = []
        for i in range(0, blocks):
            start = i * block_size_bytes
            end = (i + 1) * block_size_bytes
            block = M[start:end]
            block_array = []
            for j in range(0, 16):
                start = j * word_size_bytes
                end = (j + 1) * word_size_bytes
                int1 = int.from_bytes(block[start:end], "big")
                block_array.append(int1)
            returnArray.append(block_array)
        
        return returnArray

    # 6.2.1
    def hash_256(self, M: bytes):
        M = self.padMessage_256(M)
        M = self.ParseMessage(M)

        # setup a - f from initial hash values
        H = []
        H_0 = [
            self.initial_hash_value[0],
            self.initial_hash_value[1],
            self.initial_hash_value[2],
            self.initial_hash_value[3],
            self.initial_hash_value[4],
            self.initial_hash_value[5],
            self.initial_hash_value[6],
            self.initial_hash_value[7]
        ] 
        H.append(H_0)
        for n in range(0, len(M)):
            W = M[n]
            for t in range(16, 64):
                temp1 = self.sigma_256_1(W[t - 2])
                temp2 = self.sigma_256_0(W[t - 15])
                temp3 = SHA2_Instance.add(temp1, W[t - 7], self.word_size)
                temp3 = SHA2_Instance.add(temp3, temp2, self.word_size)
                W.append(SHA2_Instance.add(temp3, W[t-16], self.word_size))

            a = H[n][0]
            b = H[n][1]
            c = H[n][2]
            d = H[n][3]
            e = H[n][4]
            f = H[n][5]
            g = H[n][6]
            h = H[n][7]
            for t in range(0, 64):
                temp1 = SHA2_Instance.add(h, self.SIGMA_256_1(e), self.word_size)
                temp1 = SHA2_Instance.add(temp1, SHA2_Instance.Ch(e, f, g, 32), self.word_size)
                temp1 = SHA2_Instance.add(temp1, self._K_256[t], self.word_size)
                temp1 = SHA2_Instance.add(temp1, W[t], self.word_size)

                T_1 = temp1
                T_2 = SHA2_Instance.add(self.SIGMA_256_0(a), SHA2_Instance.Maj(a, b, c, 32), self.word_size)
                h = g
                g = f
                f = e
                e = SHA2_Instance.add(d, T_1, self.word_size)
                d = c
                c = b
                b = a
                a = SHA2_Instance.add(T_1, T_2, self.word_size)
        
            H_t = []
            # H_t.append(H[n][0] + a)
            # H_t.append(H[n][1] + b)
            # H_t.append(H[n][2] + c)
            # H_t.append(H[n][3] + d)
            # H_t.append(H[n][4] + e)
            # H_t.append(H[n][5] + f)
            # H_t.append(H[n][6] + g)
            # H_t.append(H[n][7] + h)
            H_t.append(SHA2_Instance.add(H[n][0], a, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][1], b, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][2], c, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][3], d, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][4], e, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][5], f, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][6], g, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][7], h, self.word_size))
            H.append(H_t)

        n = len(H) - 1
        word_size_bytes = self.word_size // 8
        H_0_Bytes = H[n][0].to_bytes(word_size_bytes, "big")
        H_1_Bytes = H[n][1].to_bytes(word_size_bytes, "big")
        H_2_Bytes = H[n][2].to_bytes(word_size_bytes, "big")
        H_3_Bytes = H[n][3].to_bytes(word_size_bytes, "big")
        H_4_Bytes = H[n][4].to_bytes(word_size_bytes, "big")
        H_5_Bytes = H[n][5].to_bytes(word_size_bytes, "big")
        H_6_Bytes = H[n][6].to_bytes(word_size_bytes, "big")
        H_7_Bytes = H[n][7].to_bytes(word_size_bytes, "big")

        returnByteArray = bytearray()
        returnByteArray.extend(H_0_Bytes)
        returnByteArray.extend(H_1_Bytes)
        returnByteArray.extend(H_2_Bytes)
        returnByteArray.extend(H_3_Bytes)
        returnByteArray.extend(H_4_Bytes)
        returnByteArray.extend(H_5_Bytes)
        returnByteArray.extend(H_6_Bytes)
        returnByteArray.extend(H_7_Bytes)

        return bytes(returnByteArray)
    
    # 6.3
    def hash_224(self, M: bytes):
        returnByteArray = self.hash_256(M)
        # only subset the left 224 bits
        returnBytesLen = 224 // 8
        return returnByteArray[0:returnBytesLen]

    # 6.4
    def hash_512(self, M: bytes):
        M = self.padMessage_512(M)
        M = self.ParseMessage(M)

        # setup a - f from initial hash values
        H = []
        H_0 = [
            self.initial_hash_value[0],
            self.initial_hash_value[1],
            self.initial_hash_value[2],
            self.initial_hash_value[3],
            self.initial_hash_value[4],
            self.initial_hash_value[5],
            self.initial_hash_value[6],
            self.initial_hash_value[7]
        ] 
        H.append(H_0)
        for n in range(0, len(M)):
            W = M[n]
            for t in range(16, 80):
                temp1 = self.sigma_512_1(W[t - 2])
                temp2 = self.sigma_512_0(W[t - 15])
                temp3 = SHA2_Instance.add(temp1, W[t - 7], self.word_size)
                temp3 = SHA2_Instance.add(temp3, temp2, self.word_size)
                W.append(SHA2_Instance.add(temp3, W[t-16], self.word_size))

            a = H[n][0]
            b = H[n][1]
            c = H[n][2]
            d = H[n][3]
            e = H[n][4]
            f = H[n][5]
            g = H[n][6]
            h = H[n][7]
            for t in range(0, 80):
                temp1 = SHA2_Instance.add(h, self.SIGMA_512_1(e), self.word_size)
                temp1 = SHA2_Instance.add(temp1, SHA2_Instance.Ch(e, f, g, 64), self.word_size)
                temp1 = SHA2_Instance.add(temp1, self._K_512[t], self.word_size)
                temp1 = SHA2_Instance.add(temp1, W[t], self.word_size)

                T_1 = temp1
                T_2 = SHA2_Instance.add(self.SIGMA_512_0(a), SHA2_Instance.Maj(a, b, c, 64), self.word_size)
                h = g
                g = f
                f = e
                e = SHA2_Instance.add(d, T_1, self.word_size)
                d = c
                c = b
                b = a
                a = SHA2_Instance.add(T_1, T_2, self.word_size)
        
            H_t = []
            # H_t.append(H[n][0] + a)
            # H_t.append(H[n][1] + b)
            # H_t.append(H[n][2] + c)
            # H_t.append(H[n][3] + d)
            # H_t.append(H[n][4] + e)
            # H_t.append(H[n][5] + f)
            # H_t.append(H[n][6] + g)
            # H_t.append(H[n][7] + h)
            H_t.append(SHA2_Instance.add(H[n][0], a, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][1], b, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][2], c, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][3], d, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][4], e, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][5], f, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][6], g, self.word_size))
            H_t.append(SHA2_Instance.add(H[n][7], h, self.word_size))
            H.append(H_t)

        n = len(H) - 1
        word_size_bytes = self.word_size // 8
        H_0_Bytes = H[n][0].to_bytes(word_size_bytes, "big")
        H_1_Bytes = H[n][1].to_bytes(word_size_bytes, "big")
        H_2_Bytes = H[n][2].to_bytes(word_size_bytes, "big")
        H_3_Bytes = H[n][3].to_bytes(word_size_bytes, "big")
        H_4_Bytes = H[n][4].to_bytes(word_size_bytes, "big")
        H_5_Bytes = H[n][5].to_bytes(word_size_bytes, "big")
        H_6_Bytes = H[n][6].to_bytes(word_size_bytes, "big")
        H_7_Bytes = H[n][7].to_bytes(word_size_bytes, "big")

        returnByteArray = bytearray()
        returnByteArray.extend(H_0_Bytes)
        returnByteArray.extend(H_1_Bytes)
        returnByteArray.extend(H_2_Bytes)
        returnByteArray.extend(H_3_Bytes)
        returnByteArray.extend(H_4_Bytes)
        returnByteArray.extend(H_5_Bytes)
        returnByteArray.extend(H_6_Bytes)
        returnByteArray.extend(H_7_Bytes)

        return bytes(returnByteArray)

    # 6.5
    def hash_384(self, M: bytes):
        returnByteArray = self.hash_512(M)
        returnBytesLen = 384 // 8
        return returnByteArray[0:returnBytesLen]

    # 6.6
    def hash_512_224(self, M: bytes):
        returnByteArray = self.hash_512(M)
        returnBytesLen = 224 // 8
        return returnByteArray[0:returnBytesLen]

    # 6.7
    def hash_512_256(self, M: bytes):
        returnByteArray = self.hash_512(M)
        returnBytesLen = 256 // 8
        return returnByteArray[0:returnBytesLen]
    
    # proxy function
    def hash(self, M: bytes):
        if (self.sha2 == SHA2.SHA2_224):
            return self.hash_224(M)
        elif (self.sha2 == SHA2.SHA2_256):
            return self.hash_256(M)
        elif (self.sha2 == SHA2.SHA2_384):
            return self.hash_384(M)
        elif (self.sha2 == SHA2.SHA2_512):
            return self.hash_512(M)
        elif (self.sha2 == SHA2.SHA2_512_224):
            return self.hash_512_224(M)
        elif (self.sha2 == SHA2.SHA2_512_256):
            return self.hash_512_256(M)



if __name__ == "__main__":
    x = SHA2_Instance(SHA2.SHA2_256)
    # string = b'Hello World'
    string = b'abc'
    # print(x.hash_256(string))
    # print(x.hash_224(string))
    print(x.hash(string))
    
    y = hashes.Hash(hashes.SHA256())
    y.update(string)
    print(y.finalize())

    # TODO: FINISH 224, 384, 512, 512/224, and 512/256

