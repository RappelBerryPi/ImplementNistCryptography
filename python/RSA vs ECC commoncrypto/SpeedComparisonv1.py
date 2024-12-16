import ctypes
import ctypes.util
import os
import base64
import binascii
import datetime
libname = ctypes.util.find_library('System')
if not libname:
    raise OSError('Library not found')

crypto = ctypes.CDLL(os.path.basename(libname))

class ccrsa_pub_ctx(ctypes.Structure):
    _fields_ = [
        ('pb_n', ctypes.c_size_t),
        ('pb_bitlen', ctypes.c_uint64),
        ('pb_funcs', ctypes.c_void_p),
        ('pb_ccn', ctypes.c_wchar_p)]

class CCRSACryptor(ctypes.Structure):
    _fields_ = [('key_nbits', ctypes.c_size_t),
                ('keyType', ctypes.c_uint32),
                ('fk', ctypes.POINTER(ccrsa_pub_ctx) * 2)]
class ccec_const_cp(ctypes.Structure):
    _fields_ = [
        ('n', ctypes.c_size_t),
        ('bitlen', ctypes.c_uint64),
        ('funcs', ctypes.c_void_p),
        ('ccn', ctypes.c_wchar_p)
    ]
    
class ccec_projective_point(ctypes.Structure):
    _fields_ = [
        ('xyz', ctypes.c_uint64)
    ]
    
class ccec_full_ctx(ctypes.Structure):
    _fields_ = [
        ('cp', ctypes.POINTER(ccec_const_cp)),
        ('point', ccec_projective_point)
    ]
    
class ccec_pub_ctx(ctypes.Structure):
    _fields_ = [
         ('cp', ctypes.POINTER(ccec_const_cp)),
         ('point', ccec_projective_point)
    ]

class ecKey(ctypes.Union):
    _fields_ = [
        ('private', ctypes.POINTER(ccec_full_ctx)),
        ('public', ctypes.POINTER(ccec_pub_ctx)),
        ('bytes', ctypes.POINTER(ctypes.c_uint8))
    ]
    
class CCECCryptor(ctypes.Structure):
    _fields_ = [
        ('ecKey', ecKey),
        ('key_nbits', ctypes.c_size_t),
        ('keyType', ctypes.c_uint32)
    ]

# RSA 
crypto.CCRSACryptorGeneratePair.restype = ctypes.c_int
crypto.CCRSACryptorGeneratePair.argtypes = [ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(CCRSACryptor)), ctypes.POINTER(ctypes.POINTER(CCRSACryptor))]

crypto.CCRSACryptorSign.restype = ctypes.c_int
crypto.CCRSACryptorSign.argtypes = [ctypes.POINTER(CCRSACryptor), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_char_p,  ctypes.POINTER(ctypes.c_size_t) ]

crypto.CCRSACryptorVerify.restype = ctypes.c_int
crypto.CCRSACryptorVerify.argtypes = [ctypes.POINTER(CCRSACryptor), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

# hashing
crypto.CCDigest.restype = ctypes.c_int
crypto.CCDigest.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]

# ec
crypto.CCECCryptorGeneratePair.restype = ctypes.c_int
crypto.CCECCryptorGeneratePair.argtypes = [ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(CCECCryptor)), ctypes.POINTER(ctypes.POINTER(CCECCryptor))]

crypto.CCECCryptorSignHash.restype = ctypes.c_int
crypto.CCECCryptorSignHash.argtypes = [ctypes.POINTER(CCECCryptor), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,  ctypes.POINTER(ctypes.c_size_t) ]

crypto.CCECCryptorVerifyHash.restype = ctypes.c_int
crypto.CCECCryptorVerifyHash.argtypes = [ctypes.POINTER(CCECCryptor), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]

def rsaGenKeys(size = 2048):
    RSASize = ctypes.c_size_t(size)
    e = ctypes.c_uint32(65537)
    publicKey = ctypes.pointer(ctypes.pointer(CCRSACryptor()))
    privateKey = ctypes.pointer(ctypes.pointer(CCRSACryptor()))
    
    ret = crypto.CCRSACryptorGeneratePair(RSASize, e, publicKey, privateKey)
    
    return publicKey, privateKey

def rsaSign(privateKey, hash, digest, padding, salt, sign_len):
    # hash -> c_out (digest output)
    signed_data = ctypes.create_string_buffer(sign_len)
    signed_data_len = ctypes.pointer(ctypes.c_size_t(sign_len))
    
    ret = crypto.CCRSACryptorSign(privateKey.contents, padding, hash, hash_len, digest, salt, signed_data, signed_data_len)
    return signed_data
    
def rsaVerify(publicKey, hash, digest, padding, salt, signature, sign_len):
    valid = ctypes.pointer(ctypes.c_uint32())
    ret = crypto.CCRSACryptorVerify(publicKey.contents, padding, hash, hash_len, digest, salt, signature, sign_len)
    # print(ret)

def ecGenKeys(curveSize: int = 256):
    ECSize = ctypes.c_size_t(curveSize)
    publicKey = ctypes.pointer(ctypes.pointer(CCECCryptor()))
    privateKey = ctypes.pointer(ctypes.pointer(CCECCryptor()))
   
    ret = crypto.CCECCryptorGeneratePair(ECSize, publicKey, privateKey)
    return publicKey, privateKey

def ecSign(privateKey, hash):
    # hash = c_out
    signed_data = ctypes.create_string_buffer(privateKey.contents.contents.key_nbits)
    signed_data_len = ctypes.pointer(ctypes.c_size_t(privateKey.contents.contents.key_nbits))
    
    ret = crypto.CCECCryptorSignHash(privateKey.contents, hash, hash_len, signed_data, signed_data_len)
    return  signed_data, signed_data_len.contents
    #x = signed_data[:256].hex().strip('0')
    #print(x)
    #print(len(x))
    
def ecVerify(publicKey, hash, signature, sign_len):
    isValid = ctypes.pointer(ctypes.c_uint32())
    ret = crypto.CCECCryptorVerifyHash(publicKey.contents, hash, hash_len, signature, sign_len, isValid)
    # print(isValid.contents.value)

def hash(data):
    hash_len = 32
    c_hashfunc = ctypes.c_uint32(10) # sha-256
    c_data = ctypes.c_char_p(data)
    in_len = ctypes.c_size_t(len(data))
    c_out = ctypes.create_string_buffer(hash_len)
    
    ret = crypto.CCDigest(c_hashfunc, c_data, in_len, c_out)
    return c_out

def rsaTest(rsa_key_size, loopCount):
    sign_len = rsa_key_size // 8
    publicRSAKey, privateRSAKey = rsaGenKeys(rsa_key_size)
    digest = ctypes.c_uint32(10) # sha-256
    padding = ctypes.c_uint32(1005)
    salt = ctypes.c_size_t(4)
    signatures = []
    
    ## sign
    startTime = datetime.datetime.now()
    for i in range(0,loopCount):
        signature = rsaSign(privateRSAKey, c_out, digest, padding, salt, sign_len)
        signatures.append(signature)
            
    endTime = datetime.datetime.now()
    
    sign_total_time = (endTime - startTime).total_seconds()
    signs_per_second = loopCount / sign_total_time
    print(f"RSA ({rsa_key_size}) Signatures per second: {signs_per_second}")
    
    ##verify
    startTime = datetime.datetime.now()
    for signature in signatures:
        rsaVerify(publicRSAKey, c_out, digest, padding, salt, signature, sign_len)
    endTime = datetime.datetime.now()
    
    ver_total_time = (endTime - startTime).total_seconds()
    vers_per_second = loopCount / ver_total_time
    print(f"RSA ({rsa_key_size}) Signature verifications per second: {vers_per_second}")
    print()
    return sign_total_time, ver_total_time
    
def ecTest(ec_key_size, loopCount):
    publicECKey, privateECKey = ecGenKeys(ec_size)

    ## sign
    signatures = []
    startTime = datetime.datetime.now()
    for i in range(0,loopCount):
        signature, sign_len = ecSign(privateECKey, c_out)
        signatures.append((signature, sign_len))
        # c_out[0] = b'\xbb'
     
    endTime = datetime.datetime.now()
    sign_total_time = (endTime - startTime).total_seconds()
    sigs_per_second = loopCount / sign_total_time
    print(f"ECDSA ({ec_size}) Signatures per second: {sigs_per_second}")
    
    ## verify
    startTime = datetime.datetime.now()
    for signature, sign_len in signatures:
        ecVerify(publicECKey, c_out, signature, sign_len)
    endTime = datetime.datetime.now()
    
    ver_total_time = (endTime - startTime).total_seconds()
    vers_per_second = loopCount / ver_total_time
    print(f"ECDSA ({ec_size}) Signature verifications per second: {vers_per_second}")
    print()
    return sign_total_time, ver_total_time


data = b"abc"
hash_len = 32
c_out = hash(data)
loopCount = 10000

# EC
ec_sizes = [256, 384, 521]
print("ECDSA")
for ec_size in ec_sizes:
    total_sign_time = 0.0
    total_verification_time = 0.0
    for i in range(0,5):
        sign_total_time, ver_total_time = ecTest(ec_size, loopCount)
        total_sign_time += sign_total_time
        total_verification_time += ver_total_time
    avg_sign_time = total_sign_time / 5
    avg_verify_time = total_verification_time / 5
    signs_per_second = loopCount / avg_sign_time
    verifies_per_second = loopCount / avg_verify_time
    print(f"ECDSA 5 run average ({ec_size}) Signs/second: {signs_per_second}")
    print(f"ECDSA 5 run average ({ec_size}) Verifications/second: {verifies_per_second}")
    print("\n")

# rsa
print("RSA")
rsa_sizes = [2048, 3072, 4096]
for rsa_key_size in rsa_sizes:
    total_sign_time = 0.0
    total_verification_time = 0.0
    for i in range(0,5):
        sign_total_time, ver_total_time = rsaTest(rsa_key_size, loopCount)
        total_sign_time += sign_total_time
        total_verification_time += ver_total_time
    avg_sign_time = total_sign_time / 5
    avg_verify_time = total_verification_time / 5
    signs_per_second = loopCount / avg_sign_time
    verifies_per_second = loopCount / avg_verify_time
    print(f"RSA 5 run average ({rsa_key_size}) Signs/second: {signs_per_second}")
    print(f"RSA 5 run average ({rsa_key_size}) Verifications/second: {verifies_per_second}")
    print("\n")
    