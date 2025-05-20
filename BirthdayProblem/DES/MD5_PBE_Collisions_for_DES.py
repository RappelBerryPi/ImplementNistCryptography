import hashlib

# assume same length
def andBytes(bytes1: bytes, bytes2: bytearray):
    bytes1 = bytearray(bytes1).copy()
    for i in range(0,len(bytes1)):
        bytes1[i] = bytes1[i] & bytes2[i]
    return bytes(bytes1)


inp = input("Please enter some text: ")

truncated_hashes = {}
rounds = 5_000_000_000
trunc_bytes = 6
and_bytes = bytearray([0xfe] * trunc_bytes)

last_hash = hashlib.md5(inp.encode("utf-8")).digest()
truncated_hash =  andBytes(last_hash[0:trunc_bytes], and_bytes)
value = truncated_hashes.get(truncated_hash, 0)
truncated_hashes[truncated_hash] = value + 1
found_duplicate = False

for i in range(1, rounds):
    last_hash = hashlib.md5(last_hash).digest()
    truncated_hash =  andBytes(last_hash[0:trunc_bytes], and_bytes)
    value = truncated_hashes.get(truncated_hash, 0)
    truncated_hashes[truncated_hash] = value + 1
    if (value != 0):
        print("duplicate hash found {}".format(truncated_hash.hex()))
        print("found after {} hashes for {} byte length".format(i, trunc_bytes))
        break
