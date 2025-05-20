import hashlib

inp = input("Please enter some text: ")

truncated_hashes = {}
rounds = 5_000_000_000
trunc_bytes = 4

last_hash = hashlib.md5(inp.encode("utf-8")).digest()
truncated_hash = last_hash[0:trunc_bytes]
value = truncated_hashes.get(truncated_hash, 0)
truncated_hashes[truncated_hash] = value + 1
found_duplicate = False

for i in range(1, rounds):
    last_hash = hashlib.md5(last_hash).digest()
    truncated_hash = last_hash[0:trunc_bytes]
    value = truncated_hashes.get(truncated_hash, 0)
    truncated_hashes[truncated_hash] = value + 1
    if (value != 0):
        print("duplicate hash found {}".format(truncated_hash.hex()))
        print("found after {} hashes for {} byte length".format(i, trunc_bytes))
        break