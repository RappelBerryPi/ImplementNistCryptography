import sys
import math
import os
import random

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

    # NIST SP 800-56B 6.3.1.1
    def RSAKPG1_basic(self, strength: int, nBits: int, e: int, hashFunction: SHA2.SHA2.SHA2):
        #1.a
        if (strength < 112 or strength > 256):
            raise ValueError("strength is not acceptable")
        
        if (strength > self.ES(nBits)):
            raise ValueError("modulus length is not acceptable for strength")
        
        if (e % 2 == 0 or (e < 65537) or (e > (2**256) - 1)):
            return ValueError("exponent out of range")
        
        loop = True
        #2
        while (loop):
            #TODO: generate p and q in compliance with FIPS 186
            p, q = self.generatePandQ(nBits, e, hashFunction)
    
            #3
            d = self.mod_inv(e, n) % math.lcm(p - 1, q - 1)
            if (d > 2**(nBits // 2)):
                loop = False

        #4
        n = p * q
        
        #5
        m = random.randint(1, n - 1)

        m_prime = pow(m, e, n)
        m_prime = pow(m_prime, d, n)
        if (m_prime == m):
            raise ValueError("Pair-Wise Consistancy Test Failure")
        
        #6
        self.public_key.e = e
        self.public_key.n = n
        self.private_key.d = d
        self.private_key.n = n


    def egcd(self, number1: int, number2: int):
        if number1 == 0:
            return number2, 0, 1
        else:
            g, y, x = egcd(number2 % number1, number1)
            return g, x - (number2 // number1) * y, y
    
    # taken from tinyec
    def mod_inv(self, number: int, modulus: int):
        if number < 0:
            return modulus - mod_inv(-number, modulus)
        g, x, y = egcd(number, modulus)
        if g != 1:
            raise ArithmeticError("Modular inverse does not exist")
        else:
            return x % modulus

    # def mod_inv(self, exponent: int, modulus: int):
        # testing github copilot
        # if modulus <= 0:
        #     raise ValueError("modulus must be positive")
        # old_r, remainder = exponent, modulus
        # old_s, coefficient = 1, 0
        # while remainder != 0:
        #     quotient = old_r // remainder
        #     old_r, remainder = remainder, old_r - quotient * remainder
        #     old_s, coefficient = coefficient, old_s - quotient * coefficient
        # if old_r != 1:
        #     raise ValueError("inverse does not exist")
        # return old_s % modulus

    # FIPS 186-5 5.1 and A.1. Going with option A. to generate P and Q as primes, not the ones with conditions. WOuld
    # prefer to generate provable primes over probable primes.
    def generatePandQ(self, nlen: int, e: int, hashFunction: SHA2.SHA2.SHA2):
        isSuccessful, P, Q = self.generateProvablePrime(nlen, e, hashFunction)
        if (isSuccessful):
            return P, Q
        else:
            raise ValueError("Failure")

    # FIPS 186-5 A.1.2.1
    def getSeed(self, nlen: int):
        #1 (section 5.1 constraint)
        if (nlen < 2048):
            raise ValueError("Failure")
        #2 
        security_strength = self.ES(nlen)

        #3
        seed = os.urandom(2 * security_strength)
        return seed

    #FIPS 186-5 A.1.2.2
    def generateProvablePrime(self, nlen: int, e: int, seed: bytes, hashFunction: SHA2.SHA2.SHA2):
        #1
        if (nlen < 2048):
            raise ValueError("FAILURE")

        #2
        if (e % 2 == 0 or (e < 65537) or (e > (2**256) - 1)):
            return ValueError("FAILURE")

        #3 
        security_strength = self.ES(nlen)

        #4
        if (len(seed) < (2 * security_strength)):
            return ValueError("FAILURE")
        
        #5
        working_seed = bytearray(seed).copy()

        #6 generate p
        #6.1
        L = nlen//2
        N1 = 1
        N2 = 1
        first_seed = working_seed.copy()

        # this function raises an exception and as such does not need to be caught. 
        isSuccsessful, p, p1, p2, pseed = self.provable_prime_construction(L, N1, N2, first_seed, e, hashFunction)

        if (not isSuccsessful):
            return ValueError("FAILURE")

        #6.2
        working_seed = pseed.copy()

        while True:
            #7 generate q
            #7.1
            L = nlen//2
            N1 = 1
            N2 = 1
            first_seed = working_seed.copy()

            isSuccsessful, q, q1, q2, qseed = self.provable_prime_construction(L, N1, N2, first_seed, e, hashFunction)

            if (not isSuccsessful):
                return ValueError("FAILURE")

            #7.2
            working_seed = qseed.copy()

            #8
            if ((p - q).bit_length() <= 2**((nlen / 2) - 100)):
                break

        #9
        pseed.clear() 
        qseed.clear()
        working_seed.clear()

        #10
        return True, p, q


    #FIPS 186-5 B.10
    def provable_prime_construction(self, L: int, N1: int, N2: int, first_seed: bytearray, e: int, hashFunction: SHA2.SHA2.SHA2):
        #1 (skipping as all input is forced and would be acceptable)
        #2
        if (N1 == 1):
            P1 = 1
            P2_seed = first_seed.copy()
        #3
        else:
            try:
                P1, P2_seed = self.Shawne_Taylor_Random_Prime_Routine(N1, first_seed.copy())
            except:
                return False, 0, 0, 0, 0

        #4
        if (N2 == 1):
            P2 = 1
            P0_seed = P2_seed.copy()
        #5
        else:
            try:
                P2, P0_seed = self.Shawne_Taylor_Random_Prime_Routine(N2, P2_seed.copy())
            except:
                return False, 0, 0, 0, 0
        #6
        length = math.ceil(L/2) + 1
        P0, pseed = self.Shawne_Taylor_Random_Prime_Routine(length, P0_seed.copy())

        #7
        if (math.gcd(P0, P1, P2) != 1):
            return False, 0, 0, 0, 0
        
        #8
        Sha2_hashfunction = SHA2.SHA2.SHA2_Instance(hashFunction)
        iterations = math.ceil(L / Sha2_hashfunction.message_digest_size) - 1

        #9
        pgen_counter = 0

        #10
        x = 0

        #11
        for i in range(0, iterations):
            x = x + (Sha2_hashfunction.hash(pseed + i)) * 2**(i * Sha2_hashfunction.message_digest_size)

        #12
        pseed = pseed + iterations + 1

        #13
        # missing a variable here in the NIST documentation, assuming it's sqrt(2)
        temp = math.floor(math.sqrt(2) * 2**(L - 1))
        x = temp + x % (2**L - temp)

        #14 y is [1,p2] and (y * p0 * p1 - 1) == 0 mod p2
        y = self.mod_inv(P0 * P1, P2)

        #15
        temp = 2 * y * P0 * P1
        t = math.ceil((temp + x)/(temp))

        #16
        #TODO: start here and finish
        
    #B.6
    def Shawne_Taylor_Random_Prime_Routine(self, length: int, input_seed: bytearray):
        pass
        

    # helper function that vlidates the input sizes for all the primitives
    def check_input_size(self, message_or_ciphertext: int, n: int):
        if (message_or_ciphertext < 0 or message_or_ciphertext > n - 1):
            raise ValueError("message representative out of range")

    # NIST SP 800-56B Table 2 and functions. Estimated Security Strength of Modulus Size.
    def ES(self, modulus_length: int):
        if (modulus_length < 3072):
            return 112
        if (modulus_length < 4096):
            return 128
        if (modulus_length < 6144):
            return 152
        if (modulus_length < 8192):
            return 176
        if (modulus_length >= 8192):
            return 200


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