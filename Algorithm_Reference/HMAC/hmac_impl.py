from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as hm

def hmac(H : hashes.HashAlgorithm, K : bytes, text: bytes):
    B = H.block_size
    L = H.digest_size

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    # Step 1
    if (len(K) == B):
        pass
    # Step 2
    elif (len(K) > B): 
        digest = hashes.Hash(H)
        digest.update(K)
        K = digest.finalize()
        K2 = bytearray(K) 
        K3 = b'\x00' * (B - L)
        K2.extend(K3)
        K = bytes(K2)
    # Step 3
    else:
        K2 = bytearray(K)
        K3 = b'\x00' * (B - len(K))
        K2.extend(K3)
        K = bytes(K2)
    
    # Step 4
    intermediate = bytearray()
    for i in range(0, B):
        intermediate.append(K[i] ^ ipad[i])

    # Step 5
    intermediate.extend(text)

    # Step 6
    digest = hashes.Hash(H)
    digest.update(intermediate)
    intermediate = digest.finalize()

    # Step 7
    intermediate2 = bytearray()
    for i in range(0, B):
        intermediate2.append(K[i] ^ opad[i])

    # Step 8
    intermediate2.extend(intermediate)
    intermediate = bytes(intermediate2)

    # Step 9
    digest = hashes.Hash(H)
    digest.update(intermediate)
    result = digest.finalize()
    return result


print(hmac(hashes.SHA512(), b'key', b'textToHash'))

hmac2 = hm.HMAC(b'key', hashes.SHA512())
hmac2.update(b'textToHash')
print(hmac2.finalize())
