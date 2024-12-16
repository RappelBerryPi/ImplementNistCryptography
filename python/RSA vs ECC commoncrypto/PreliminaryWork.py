# https://github.com/apple-oss-distributions/CommonCrypto
# CCCryptorStatus 
# CCECCryptorSignHash(CCECCryptorRef privateKey, 
#                     const void *hashToSign, size_t hashSignLen,
#                     void *signedData, size_t *signedDataLen)
# {
#     CCCryptorStatus retval = kCC

# RSA 
# CCCryptorStatus 
# CCRSACryptorSign(CCRSACryptorRef privateKey, CCAsymmetricPadding padding, 
#                 const void *hashToSign, size_t hashSignLen,
#                 CCDigestAlgorithm digestType, size_t saltLen,
#                 void *signedData, size_t *signedDataLen)
# {    
    
# CCCryptorStatus CCRSACryptorGeneratePair(
#	size_t keysize,
#    uint32_t e,
#	CCRSACryptorRef *publicKey,_
#    CCRSACryptorRef *privateKey)
#    API_AVAILABLE(macos(10.7), ios(5.0));

#CCCryptorStatus
#CCECCryptorGeneratePair( size_t keysize,
#                         CCECCryptorRef *publicKey,
#                         CCECCryptorRef *privateKey)
#API_AVAILABLE(macos(10.7), ios(5.0));

# e needs to be 65537 or bigger. but 65537 is common
    
import ctypes
import ctypes.util
import os
import base64
import binascii
libname = ctypes.util.find_library('System')
if not libname:
    raise OSError('Library not found')

crypto = ctypes.CDLL(os.path.basename(libname))

#enum {
#    ccRSAKeyPublic          = 0,
#    ccRSAKeyPrivate         = 1,
#    ccRSABlankPublicKey     = 97,
#    ccRSABlankPrivateKey    = 98,
#    ccRSABadKey             = 99,
#};
#typedef uint32_t CCRSAKeyType;

#typedef struct _CCRSACryptor {
#    size_t key_nbits;
#    CCRSAKeyType keyType;
#    struct ccrsa_full_ctx fk[];
#} CCRSACryptor;

#struct ccrsa_pub_ctx {
#     cczp zm;
#     cc_unit m[n];
#     cc_unit m0inv;
#     cc_unit mr2[n];
#     cc_unit e[n];
# }

# struct ccrsa_priv_ctx {
#     cc_unit d[n];        // e^(-1) mod lcm(p-1, q-1)

#     cczp zp;
#     cc_unit p[n/2+1];
#     cc_unit p0inv;
#     cc_unit pr2[n/2+1];

#     cczp zq;
#     cc_unit q[n/2+1];
#     cc_unit q0inv;
#     cc_unit qr2[n/2+1];

#     cc_unit dp[n/2+1];   // d mod (p-1)
#     cc_unit dq[n/2+1];   // d mod (q-1)
#     cc_unit qinv[n/2+1]; // q^(-1) mod p
# }

# struct ccrsa_full_ctx {
#     struct ccrsa_pub_ctx;
#     struct ccrsa_priv_ctx;
# }

# typedef uint64_t cc_unit;
# typedef size_t  cc_size;

# struct cczp;

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
    
def rsaSign():
    crypto.CCRSACryptorGeneratePair.restype = ctypes.c_int
    
    RSASize = ctypes.c_size_t(2048)
    e = ctypes.c_uint32(65537)
    publicKey = ctypes.pointer(ctypes.pointer(CCRSACryptor()))
    privateKey = ctypes.pointer(ctypes.pointer(CCRSACryptor()))
   
    crypto.CCRSACryptorGeneratePair.argtypes = [ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(CCRSACryptor)), ctypes.POINTER(ctypes.POINTER(CCRSACryptor))]
    
    ret = crypto.CCRSACryptorGeneratePair(RSASize, e, publicKey, privateKey)
    #print(publicKey.contents.fk[0])
    #print(privateKey.contents.contents.keyType)
    
    #hash
    data = b"abc"
    hash_len = 32
    c_hashfunc = ctypes.c_uint32(10)
    c_data = ctypes.c_char_p(data)
    hash_in_len = ctypes.c_size_t(len(data))
    c_out = ctypes.create_string_buffer(hash_len)
    
    crypto.CCDigest.restype = ctypes.c_int
    crypto.CCDigest.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    ret = crypto.CCDigest(c_hashfunc, c_data, hash_in_len, c_out)
    
    # rsa sign
    crypto.CCRSACryptorSign.restype = ctypes.c_int
    
    digest = ctypes.c_uint32(10) # sha-256
    padding = ctypes.c_uint32(1005)
    salt = ctypes.c_size_t(4)
    signed_data = ctypes.create_string_buffer(256)
    signed_data_len = ctypes.pointer(ctypes.c_size_t(256))
    
    crypto.CCRSACryptorSign.argtypes = [ctypes.POINTER(CCRSACryptor), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_char_p,  ctypes.POINTER(ctypes.c_size_t) ]
    
    ret = crypto.CCRSACryptorSign(privateKey.contents, padding, c_out, hash_len, digest, salt, signed_data, signed_data_len)
    print(signed_data[:256])
    
# CCCryptorStatus
#CCRSACryptorSign(	CCRSACryptorRef privateKey,
#					CCAsymmetricPadding padding,
#                 	const void *hashToSign,
#                    size_t hashSignLen,
#                 	CCDigestAlgorithm digestType,
#                    size_t saltLen,
#                 	void *signedData,
#                    size_t *signedDataLen)    
    
# rsaSign()

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

# typedef struct _CCECCryptor {
#     union {
#        ccec_full_ctx_t private;
#        ccec_pub_ctx_t public;
#        uint8_t *bytes;
#    } ecKey;
#    size_t key_nbits;
#    CCECKeyType keyType;
#} CCECCryptor;

#TODO: find keyrype, fine ful and pub ctx

# typedef struct ccec_full_ctx* ccec_full_ctx_t;
# typedef struct ccec_pub_ctx* ccec_pub_ctx_t;

# struct ccec_full_ctx {
#     ccec_const_cp_t cp;
#     CC_ALIGNED(16) struct ccec_projective_point point[];
# } CC_ALIGNED(16);

# struct ccec_pub_ctx {
#     ccec_const_cp_t cp;
#     CC_ALIGNED(16) struct ccec_projective_point point[];
# } CC_ALIGNED(16);

# typedef const struct ccec_cp* ccec_const_cp_t;

# typedef ccec_projective_point* ccec_projective_point_t;

# struct ccec_projective_point {
#     cc_unit xyz[1];
# } CC_ALIGNED(8);
# typedef struct ccec_projective_point ccec_projective_point;

# struct ccec_cp {
#    __CCZP_ELEMENTS_DEFINITIONS()
#} CC_ALIGNED(CCN_UNIT_SIZE);

#define __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
#     cc_size pre##n;                             \
#     cc_unit pre##bitlen;                        \
#     cczp_funcs_t pre##funcs;

#define __CCZP_ELEMENTS_DEFINITIONS(pre)    \
#     __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
#     cc_unit pre##ccn[];

# typedef struct _CCECCryptor *CCECCryptorRef;

def ecSign():
    crypto.CCECCryptorGeneratePair.restype = ctypes.c_int
    
    ECSize = ctypes.c_size_t(256)
    publicKey = ctypes.pointer(ctypes.pointer(CCECCryptor()))
    privateKey = ctypes.pointer(ctypes.pointer(CCECCryptor()))
   
    crypto.CCECCryptorGeneratePair.argtypes = [ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(CCECCryptor)), ctypes.POINTER(ctypes.POINTER(CCECCryptor))]
    
    ret = crypto.CCECCryptorGeneratePair(ECSize, publicKey, privateKey)
    #print(publicKey.contents.fk[0])
    #print(privateKey.contents.contents.keyType)
    
    #hash
    data = b"abc"
    hash_len = 32
    c_hashfunc = ctypes.c_uint32(10)
    c_data = ctypes.c_char_p(data)
    hash_in_len = ctypes.c_size_t(len(data))
    c_out = ctypes.create_string_buffer(hash_len)
    
    crypto.CCDigest.restype = ctypes.c_int
    crypto.CCDigest.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    ret = crypto.CCDigest(c_hashfunc, c_data, hash_in_len, c_out)
    
    # rsa sign
    crypto.CCECCryptorSignHash.restype = ctypes.c_int
    
    digest = ctypes.c_uint32(10) # sha-256
    padding = ctypes.c_uint32(1005)
    salt = ctypes.c_size_t(4)
    signed_data = ctypes.create_string_buffer(256)
    signed_data_len = ctypes.pointer(ctypes.c_size_t(256))
    
    # TODO: finish
    crypto.CCECCryptorSignHash.argtypes = [ctypes.POINTER(CCECCryptor), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,  ctypes.POINTER(ctypes.c_size_t) ]
    
    ret = crypto.CCECCryptorSignHash(privateKey.contents, c_out, hash_len, signed_data, signed_data_len)
    x = signed_data[:256].hex().strip('0')
    print(x)
    print(len(x))

ecSign()
# ccdigest -> ccdogestalgoritjm, const uint8_t *data, size_t len, uint8_t *out)

# an enum converted to an int value
# SHA-256 -> 10
# Thanks https://github.com/glisco/pbkdf2_ctypes/blob/master/pbkdf2_ctypes.py and others
# https://github.com/Apple-FOSS-Mirror/CommonCrypto/blob/master/CCRegression/CommonCrypto/CommonDigest.c
# https://github.com/Apple-FOSS-Mirror/CommonCrypto/blob/master/Source/API/CommonDigest.c
# https://docs.python.org/3/library/ctypes.html#ctypes.create_string_buffer
# https://docs.rs/commoncrypto-sys/latest/commoncrypto_sys/enum.CCDigestAlgorithm.html

def hash():
    data = b"abc"
    hash_len = 32
    c_hashfunc = ctypes.c_uint32(10)
    c_data = ctypes.c_char_p(data)
    len = ctypes.c_size_t(len(data))
    c_out = ctypes.create_string_buffer(hash_len)
    
    crypto.CCDigest.restype = ctypes.c_int
    crypto.CCDigest.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    ret = crypto.CCDigest(c_hashfunc, c_data, len, c_out)
    return c_out[:hash_len]