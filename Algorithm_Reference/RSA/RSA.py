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
    def RSASSA_PSS_SIGN(self, hashFunction: SHA2.SHA2.SHA2, message: bytes, sLen: int = 20):
        k = self.private_key.n.bit_length() // 8
        #1
        EM = self.EMSA_PSS_ENCODE(message, self.private_key.n.bit_length() - 1, hashFunction, sLen)

        #2.a.
        m = self.OS2IP(EM)

        #2.b.
        s = self.RSASP1(m)

        #2.c.
        S = self.I2OSP(s, k)
        return S

    #8.1.2
    def RSASSA_PSS_VERIFY(self, hashFunction: SHA2.SHA2.SHA2, public_key: RSA_Public_Key, message: bytes, signature: bytes, sLen = 20):
        k = public_key.n.bit_length() // 8

        #1
        if (len(signature) != k):
            raise ValueError("invalid Signature")

        #2.a.
        s = self.OS2IP(signature)

        #2.b. TODO: not catching error.
        m = self.RSAVP1(s, public_key)

        #2.c. TODO: not catching error.
        EM = self.I2OSP(m, k)

        #3
        Result = self.EMSA_PSS_VERIFY(hashFunction, message, EM, public_key.n.bit_length() - 1, sLen)
        if (Result != "consistent"):
            raise ValueError("invalid Signature")
        return "valid signature"
    
    #8.2.1
    def RSASSA_PKCS1_V1_5_SIGN(self, hashFunction: SHA2.SHA2.SHA2, message: bytes):
        #1
        k = self.private_key.n.bit_length() // 8
        EM = self.EMSA_PKCS1_V1_5_ENCODE(hashFunction, message, k)

        #2.a.
        m = self.OS2IP(EM)

        #2.b.
        s = self.RSASP1(m)

        #2.c.
        S = self.I2OSP(s, k)
        return S

    #8.2.2
    def RSASSA_PKCS1_V1_5_VERIFY(self, hashFunction: SHA2.SHA2.SHA2, public_key: RSA_Public_Key, message: bytes, signature: bytes):

        #1
        k = public_key.n.bit_length() // 8
        if (len(signature) != k):
            raise ValueError("invalid signature")

        #2.a.
        s = self.OS2IP(signature)

        #2.b. TODO: not catching error.
        m = self.RSAVP1(s, public_key)

        #2.c. TODO: not catching error.
        EM = self.I2OSP(m, k)

        #3
        EM_prime = self.EMSA_PKCS1_V1_5_ENCODE(hashFunction, message, k)

        #4
        if (AES.Utils.isEqual(EM, EM_prime)):
            return "valid signature"
        else:
            raise ValueError("invalid signature")

    #9.1.1
    def EMSA_PSS_ENCODE(self, message: bytes, emBits: int, hashFunction: SHA2.SHA2.SHA2, sLen: int = 20):
        emLen = math.ceil(emBits / 8)
        hLen = SHA2.SHA2.SHA2_Instance._SHA2_dictionary[hashFunction]["message_digest_size"] // 8
        #1
        hashFunctioninputLen = 2**64-1 # this is arbitrary. Will check FIPS 180 documentation
        if (len(message) > hashFunctioninputLen):
            raise ValueError("message too long")

        #2
        mHash = SHA2.SHA2.SHA2_Instance(hashFunction).hash(message)

        #3
        if (emLen < hLen + sLen + 2):
            raise ValueError("encoding error")

        #4
        salt = bytearray()
        if (sLen != 0):
            salt = os.urandom(sLen)
        
        #5
        M_prime = bytearray([0x00] * 8)
        M_prime.extend(mHash)
        M_prime.extend(salt)

        #6
        H = SHA2.SHA2.SHA2_Instance(hashFunction).hash(M_prime)

        #7
        PS = bytearray([0x00] * (emLen - sLen - hLen - 2))

        #8
        DB = PS.copy()
        DB.append(0x01)
        DB.extend(salt)

        #9
        dbMask = self.MGF1(hashFunction, H, emLen - hLen - 1)

        #10
        maskedDB = AES.Utils.xorBlocks(DB, dbMask)

        #11
        bits_to_set_to_zero = 8*emLen - emBits
        leftmostBits_zero = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x00]
        maskedDB[0] = maskedDB[0] & leftmostBits_zero[bits_to_set_to_zero]

        #12
        EM = maskedDB.copy()
        EM.extend(H)
        EM.append(0xbc)

        #13
        return EM

    #9.1.2
    def EMSA_PSS_VERIFY(self, hashFunction: SHA2.SHA2.SHA2, message: bytes, EM: bytes, emBits: int, sLen: int = 20):
        emLen = math.ceil(emBits / 8)
        hlen = SHA2.SHA2.SHA2_Instance._SHA2_dictionary[hashFunction]["message_digest_size"] // 8
        #1
        hashFunctioninputLen = 2**64-1 # this is arbitrary. Will check FIPS 180 documentation
        if (message is not None and len(message) > hashFunctioninputLen):
            raise ValueError("inconsistent")

        #2
        mHash = SHA2.SHA2.SHA2_Instance(hashFunction).hash(message)

        #3
        if (emLen < hlen + sLen + 2):
            raise ValueError("inconsistent")
        
        #4
        if (EM[-1] != 0xbc):
            raise ValueError("inconsistent")

        #5
        maskedDB = bytearray(EM[0:(emLen - hlen - 1)])
        H = EM[(emLen - hlen - 1): (emLen - 1)]

        #6
        leftmostBits = [0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xF8, 0xfc, 0xfe, 0xff]
        bits_to_set_to_zero = 8*emLen - emBits
        maskedDBcheck = maskedDB[0] & leftmostBits[bits_to_set_to_zero]
        if (maskedDBcheck != 0x00):
            raise ValueError("inconsistent")
        
        #7
        dbMask = self.MGF1(hashFunction, H, emLen - hlen - 1)

        #8
        DB = AES.Utils.xorBlocks(maskedDB, dbMask)

        #9
        leftmostBits_zero = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x00]
        DB[0] = DB[0] & leftmostBits_zero[bits_to_set_to_zero]

        #10
        DB_Zero_check = DB[0:(emLen - hlen - sLen - 2)].copy()
        if (not AES.Utils.isEqual(DB_Zero_check, bytearray([0x00] * (emLen - hlen - sLen - 2))) or
            DB[(emLen - hlen - sLen - 2)] != 0x01):
            raise ValueError("inconsistent")
        
        #11
        salt = DB[(len(DB) - sLen):].copy()

        #12
        M_prime = bytearray([0x00] * 8)
        M_prime.extend(mHash)
        M_prime.extend(salt)

        #13
        H_prime = SHA2.SHA2.SHA2_Instance(hashFunction).hash(M_prime)

        #14
        if (not AES.Utils.isEqual(H, H_prime)):
            raise ValueError("inconsistent")
        return "consistent"

    def EMSA_PKCS1_V1_5_ENCODE(self, hashFunction: SHA2.SHA2.SHA2, message: bytes, emLen: int):
        #1 TODO: not catching error
        H = SHA2.SHA2.SHA2_Instance(hashFunction).hash(message)

        #2
        T_Values = {
            SHA2.SHA2.SHA2.SHA2_224: bytearray([0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]),
            SHA2.SHA2.SHA2.SHA2_256: bytearray([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
            SHA2.SHA2.SHA2.SHA2_384: bytearray([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
            SHA2.SHA2.SHA2.SHA2_512: bytearray([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
            SHA2.SHA2.SHA2.SHA2_512_224: bytearray([0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c]),
            SHA2.SHA2.SHA2.SHA2_512_256: bytearray([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20]),
        }

        T = T_Values[hashFunction].copy()
        T.extend(H)
        tLen = len(T)

        #3
        if (emLen < tLen + 11):
            raise ValueError("intended encoded message length too short")
        
        #4
        PS = bytearray([0xff] * (emLen - tLen - 3))

        #5
        EM = bytearray([0x00])
        EM.append(0x01)
        EM.extend(PS)
        EM.append(0x00)
        EM.extend(T)
        
        #6
        return EM

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
    
    #TODO: implement RSAVE functions 7.2.1.2 and 7.2.1.3
    #TODO: implement key generation in NIST SP 800-56b


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
    ## private_key = rsa.generate_private_key(
    ##     public_exponent=65537,
    ##     key_size=2048,
    ## )
    ## public_key = private_key.public_key()

    ## message = b"encrypted data"
    ## # encrypt something with OAEP and SHA256
    ## ciphertext = public_key.encrypt(message, padding.PKCS1v15())


    ## # copy the private and public keys
    ## x = RSA()
    ## x.private_key.d = private_key.private_numbers().d
    ## x.private_key.n = public_key.public_numbers().n

    ## x.public_key.e = public_key.public_numbers().e
    ## x.public_key.n = public_key.public_numbers().n

    ## # decrypt what pyca/cryptography encrypted
    ## print(x.RSAES_PKCS1_V1_5_DECRYPT(ciphertext))

    ## #encrypt with my own function
    ## ciphertext = x.RSAES_PKCS1_V1_5_ENCRYPT(x.public_key, message)
    ## # decrypt using pyca/cryptography
    ## plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
    ## print(plaintext)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    message = b"data"



    # copy the private and public keys
    x = RSA()
    x.private_key.d = private_key.private_numbers().d
    x.private_key.n = public_key.public_numbers().n

    x.public_key.e = public_key.public_numbers().e
    x.public_key.n = public_key.public_numbers().n

    # works
    ## # encrypt something with OAEP and SHA256
    ## signature = private_key.sign(message, padding.PSS(
    ##     mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ##     salt_length=20 # default
    ## ), hashes.SHA256())
    ## # no error will be thrown if valid
    ## ## public_key.verify(signature, message, padding.PSS(
    ## ##     mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ## ##     salt_length=20 # default
    ## ## ), hashes.SHA256())
    ## print(x.RSASSA_PSS_VERIFY(SHA2.SHA2.SHA2.SHA2_256, x.public_key, message, signature))

    # works
    ## signature = x.RSASSA_PSS_SIGN(SHA2.SHA2.SHA2.SHA2_256, message)
    ## public_key.verify(signature, message, padding.PSS(
    ##     mgf=padding.MGF1(algorithm=hashes.SHA256()),
    ##     salt_length=20
    ## ), hashes.SHA256())

    # works
    ## signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    ## print(x.RSASSA_PKCS1_V1_5_VERIFY(SHA2.SHA2.SHA2.SHA2_256, x.public_key, message, signature))

    # works
    ## signature = x.RSASSA_PKCS1_V1_5_SIGN(SHA2.SHA2.SHA2.SHA2_256, message)
    ## # changing message to uppercase "D" causes the signature to invalidate
    ## #message = b"Data"
    ## print(public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256()))