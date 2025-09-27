from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.BrainpoolP256R1())

data = b'message'
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
print("Signature: ", end="")
print(signature.hex())
public_key = private_key.public_key()
try:
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    print("\tSignature is Valid")
except:
    print("\tSignature is not Valid")


import asn1
decoder = asn1.Decoder()
decoder.start(signature)
tag, value = decoder.read()

n = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
# n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
value_1_save = value[1]
value[1] = (-value[1]) % n

encoder = asn1.Encoder()
encoder.start()
encoder.write(value)
signature2 = encoder.output()

try:
    public_key.verify(signature2, data, ec.ECDSA(hashes.SHA256()))
    print("\tInvalid Signature is Valid")
except:
    print("\tSignature is not Valid")


mod_inv_1 = pow(value_1_save, n - 2, n)
mod_inv_2 = pow(value[1], n - 2, n)

# sanity check
assert (mod_inv_1 * value_1_save) % n == 1
assert (mod_inv_2 * value[1]) % n == 1

print(mod_inv_1 * value_1_save % n == 1)
print(mod_inv_2 * value[1] % n == 1)
print((mod_inv_1 * value[0]) % n)
print((mod_inv_2 * value[0]) % n)

print("r * s^-1 == r * -s^-1? ", end="")
print(((mod_inv_1 * value[0]) % n) == ((mod_inv_2 * value[0]) % n))