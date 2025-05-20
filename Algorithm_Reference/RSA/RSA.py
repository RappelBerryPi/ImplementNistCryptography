import sys
import math
import os

sys.path.append("../")
import SHA2.SHA2
import AES.Utils

# RFC 8017 3.1
class RSA_Public_Key:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e
    
# RFC 8017 3.2
class RSA_Private_Key:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d
    
class RSA:
    def __init__(self):
        #TODO: generate key
        self.private_key = RSA_Private_Key(0, 0)
        self.public_key = RSA_Public_Key(0, 0)

    #4.1
    def I2OSP(self, x: int, len):
        return x.to_bytes(len, byteorder="big")

    #4.2
    def OS2IP(self, x: bytes):
        return int.from_bytes(x, byteorder="big")
    
    #5.1.1
    def RSAEP(self, m: int, public_key: RSA_Public_Key):
        self.check_input_size(m, public_key.n)
        c = pow(m, public_key.e, public_key.n)
        return c

    #5.1.2
    def RSADP(self, c: int):
        self.check_input_size(c, self.private_key.n)
        m = pow(c, self.private_key.d, self.private_key.n)
        return m
    
    #5.2.1
    def RSASP1(self, m: int):
        self.check_input_size(m, self.private_key.n)
        s = pow(m, self.private_key.d, self.private_key.n)
        return s

    #5.2.2
    def RSAVP1(self, s: int, public_key: RSA_Public_Key):
        self.check_input_size(s, public_key.n)
        m = pow(s, public_key.e, public_key.n)
        return m
    
    #7.1.1
    def RSAES_OAEP_ENCRYPT(self, hashFunction: SHA2.SHA2.SHA2, public_key: RSA_Public_Key, message: bytes, L: bytes):
        #1.a.
        hashFunctioninputLen = 2**64-1 # this is arbitrary. Will check FIPS 180 documentation
        if (L is not None and len(L) > hashFunctioninputLen):
            raise ValueError("label too long")

        #1.b.
        k = public_key.n.bit_length() // 8
        mLen = len(message)
        hLen = SHA2.SHA2.SHA2_Instance._SHA2_dictionary[hashFunction]["message_digest_size"] // 8
        if (mLen > k - 2*hLen - 2):
            raise ValueError("message too long")

        #2.a.
        if (L is None):
            L = bytearray()
        lHash = SHA2.SHA2.SHA2_Instance(hashFunction).hash(L)

        #2.b.
        PS = bytearray([0x00] * (k - mLen - 2*hLen - 2))

        #2.c.
        DB = bytearray()
        DB.extend(lHash)
        DB.extend(PS)
        DB.append(0x01)
        DB.extend(message)

        #2.d.
        seed = bytearray(os.urandom(hLen))

        #2.e.
        dbMask = self.MGF1(hashFunction, seed, k - hLen - 1)
        
        #2.f.
        maskedDB = AES.Utils.xorBlocks(DB, dbMask)

        #2.g.
        seedMask = self.MGF1(hashFunction, maskedDB, hLen)

        #2.h.
        maskedSeed = AES.Utils.xorBlocks(seed, seedMask)

        #2.i.
        EM = bytearray([0x00])
        EM.extend(maskedSeed)
        EM.extend(maskedDB)

        #3.a.
        m = self.OS2IP(EM)

        #3.b.
        c = self.RSAEP(m, public_key)

        #3.c.
        C = self.I2OSP(c, k)
        return C

    #7.1.2
    def RSAES_OAEP_DECRYPT(self, hashFunction: SHA2.SHA2.SHA2, ciphertext: bytes, L: bytes):
        #1.a.
        hashFunctioninputLen = 2**64-1 # this is arbitrary. Will check FIPS 180 documentation
        if (L is not None and len(L) > hashFunctioninputLen):
            raise ValueError("decryption error")

        #1.b.
        k = self.private_key.n.bit_length() // 8
        cLen = len(ciphertext)
        if (cLen != k):
            raise ValueError("decryption error")
        
        #1.c.
        hLen = SHA2.SHA2.SHA2_Instance._SHA2_dictionary[hashFunction]["message_digest_size"] // 8
        if (k < 2*hLen + 2):
            raise ValueError("decryption error")

        #2.a.
        c = self.OS2IP(ciphertext)

        #2.b.
        m = self.RSADP(c)

        #2.c.
        EM = self.I2OSP(m, k)

        #3.a.
        if (L is None):
            L = bytearray()
        lHash = SHA2.SHA2.SHA2_Instance(hashFunction).hash(L)

        #3.b.
        Y = EM[0]
        maskedSeed = bytearray(EM[1:hLen + 1])
        maskedDB = bytearray(EM[hLen + 1:])

        #3.c.
        seedMask = self.MGF1(hashFunction, maskedDB, hLen)

        #3.d.
        seed = AES.Utils.xorBlocks(maskedSeed, seedMask)

        #3.e.
        dbMask = self.MGF1(hashFunction, seed, k - hLen - 1)

        #3.f.
        DB = AES.Utils.xorBlocks(maskedDB, dbMask)

        #3.g.
        lHash_prime = DB[0:hLen]
        i = 0
        while (DB[(hLen + i)] == 0x00):
            i += 1
        i -= 1
        PS = DB[hLen: (hLen + i)]
        oneByte = DB[((hLen + i + 1))]
        M = DB[(hLen + i + 2):]
        if (oneByte != 0x01 or not AES.Utils.isEqual(lHash, lHash_prime) or Y != 0x00):
            raise ValueError("decryption error")
        return M

    #7.2.1 - NO NIST (but for completeness sake)
    def RSAES_PKCS1_V1_5_ENCRYPT(self, public_key: RSA_Public_Key, message: bytes):

        #1
        k = public_key.n.bit_length() // 8
        mLen = len(message)
        if (mLen > k - 11):
            raise ValueError("message too long")
        
        #2.a
        PS_len = k - mLen - 3
        PS = bytearray(os.urandom(PS_len)) # can be pseudorandom, but I'm not importing random. It cannot however, be zero
        for i in range(0, len(PS)):
            if (PS[i] == 0x00):
                PS[i] = 0x01

        #2.b.
        EM = bytearray([0x00, 0x02])
        EM.extend(PS)
        EM.append(0x00)
        EM.extend(message)

        #3.a.
        m = self.OS2IP(EM)

        #3.b.
        c = self.RSAEP(m, public_key)

        #3.c.
        C = self.I2OSP(c, k)
        return C
    
    #7.2.2
    def RSAES_PKCS1_V1_5_DECRYPT(self, C: bytes):

        #1
        k = self.private_key.n.bit_length() // 8
        if (len(C) != k or k < 11):
            raise ValueError("decryption error")

        #2.a.
        c = self.OS2IP(C)

        #2.b.
        m = self.RSADP(c)

        #2.c.
        EM = self.I2OSP(m, k)

        zero_byte = EM[0]
        two_byte = EM[1]
        i = 2
        while (EM[i] != 0x00):
            i += 1
        PS = EM[2:i]
        zero_byte_2 = EM[i]
        M = EM[i+1:]
        if (zero_byte != 0x00 or
            two_byte  != 0x02 or
            len(PS)   <  8    or
            zero_byte_2 != 0x00):
            raise ValueError("decryption error")
        return M
    
    #8.1.1
    def RSASSA_PSS_SIGN(self, hashFunction: SHA2.SHA2.SHA2, message: bytes):
        #TODO: start here and finish
        pass

    #B.2.1
    def MGF1(self, hashFunction: SHA2.SHA2.SHA2, mgfSeed: bytes, maskLen: int):
        hlen = SHA2.SHA2.SHA2_Instance._SHA2_dictionary[hashFunction]["message_digest_size"] // 8
        if (maskLen > (2**32) * hlen):
            raise ValueError("MaskLen too long")
        T = bytearray()
        Hash = SHA2.SHA2.SHA2_Instance(hashFunction)
        for i in range(0, math.ceil(maskLen / hlen)):
            C = self.I2OSP(i, 4)
            input_byte_array = bytearray(mgfSeed)
            input_byte_array.extend(C)
            T.extend(Hash.hash(input_byte_array))
        return T[0:maskLen]


    # helper function that vlidates the input sizes for all the primitives
    def check_input_size(self, message_or_ciphertext: int, n: int):
        if (message_or_ciphertext < 0 or message_or_ciphertext > n - 1):
            raise ValueError("message representative out of range")

if __name__ == "__main__":

    # import RSA from pyca/cryptography
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    # works for both encrypt and decrypt
    ## private_key = rsa.generate_private_key(
    ##     public_exponent=65537,
    ##     key_size=2048,
    ## )
    ## public_key = private_key.public_key()

    ## message = b"encrypted data"
    ## # encrypt something with OAEP and SHA256
    ## ciphertext = public_key.encrypt(
    ##     message,
    ##     padding.OAEP(
    ##         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ##         algorithm=hashes.SHA256(),
    ##         label=None
    ##     )
    ## )


    ## # copy the private and public keys
    ## x = RSA()
    ## x.private_key.d = private_key.private_numbers().d
    ## x.private_key.n = public_key.public_numbers().n

    ## x.public_key.e = public_key.public_numbers().e
    ## x.public_key.n = public_key.public_numbers().n

    ## # decrypt what pyca/cryptography encrypted
    ## print(x.RSAES_OAEP_DECRYPT(SHA2.SHA2.SHA2.SHA2_256, ciphertext, None))

    ## #encrypt with my own function
    ## ciphertext = x.RSAES_OAEP_ENCRYPT(SHA2.SHA2.SHA2.SHA2_256, x.public_key, message, None)
    ## # decrypt using pyca/cryptography
    ## plaintext = private_key.decrypt(ciphertext, 
    ##     padding.OAEP(
    ##         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ##         algorithm=hashes.SHA256(),
    ##         label=None
    ##     )
    ## )
    ## print(plaintext)


    #repeat for PKCS#v1.5 padding
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    message = b"encrypted data"
    # encrypt something with OAEP and SHA256
    ciphertext = public_key.encrypt(message, padding.PKCS1v15())


    # copy the private and public keys
    x = RSA()
    x.private_key.d = private_key.private_numbers().d
    x.private_key.n = public_key.public_numbers().n

    x.public_key.e = public_key.public_numbers().e
    x.public_key.n = public_key.public_numbers().n

    # decrypt what pyca/cryptography encrypted
    print(x.RSAES_PKCS1_V1_5_DECRYPT(ciphertext))

    #encrypt with my own function
    ciphertext = x.RSAES_PKCS1_V1_5_ENCRYPT(x.public_key, message)
    # decrypt using pyca/cryptography
    plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
    print(plaintext)