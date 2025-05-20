from Crypto.Hash import MD5
from Crypto.Cipher import DES
import base64

_password = b'111' #use your own pass key
_salt = b'\xA9\x9B\xC8\x32\x56\x35\xE3\x03' #use your salt here
_iterations = 1000 #change iterations here


def getCrypt():
    hasher = MD5.new()
    hasher.update(_password)
    hasher.update(_salt)
    result = hasher.digest()

    for i in range(1, _iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()
    return DES.new(result[:8], DES.MODE_CBC, result[8:16])
	
def encrypt(password: str):
    plaintext_to_encrypt = password
    # Pad plaintext per RFC 2898 Section 6.1
    padding = 8 - len(plaintext_to_encrypt) % 8
    plaintext_to_encrypt += chr(padding) * padding
    encoder = getCrypt()
    encrypted = encoder.encrypt(plaintext_to_encrypt.encode("UTF-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt(encodedpass: str):
    enc = base64.b64decode(encodedpass)
    decoder = getCrypt()
    decrypted = decoder.decrypt(enc)
    return decrypted.rstrip(b'\2,\1,\3,\4,\5,\6,\7,\0')

x = encrypt("abc")
print(x)
y = decrypt(x)
print(y)