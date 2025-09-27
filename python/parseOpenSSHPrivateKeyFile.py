import base64

def parseOpenSSHPrivateKeyFile(filename: str):
    # read the file and keep it as a bytelike object
    content = ""
    with open(filename, 'r') as f:
        lines = f.readlines()
        lines = lines[1:-1]
        for i in range(0, len(lines)):
            content += lines[i].strip()
    content = base64.b64decode(content)

    header, next = get_header(content)
    print(f"OpenSSH Key Type: {header}")

    cipher_type, next = get_encryption_cipher(content, next)
    print(f"OpenSSH Key Encrypted by: {cipher_type}")

    kdf_type, next = get_kdf(content, next)
    print(f"OpenSSH KEK derived using: {kdf_type}")

    if (kdf_type == "none"):
        # skip 4 bytes
        next += 4
    else:
        raise Exception("not Implemented")
    
    num_of_keys, next = get_number_of_keys(content, next)
    print(f"Number of Keys in Private key file: {num_of_keys}")

    check_digit1, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit1}")
    
    key_information, next = get_public_key(content, next)
    print(f"public Key type: {key_information['key_type']}")
    if (key_information['key_type'] == "ssh-rsa"):
        print(f"\tpublic exponent: {format_int(key_information['e'])}")
        print(f"\tmodulus: {format_int(key_information['n'])}")

    check_digit2, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit2}")

    check_digit3, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit3}")

    check_digit4, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit4}")

    key_information, next = get_private_key(content, next)
    print(f"Private Key type: {key_information['key_type']}")
    if (key_information['key_type'] == "ssh-rsa"):
        print(f"\tmodulus: {format_int(key_information['n'])}")
        print(f"\tpublic exponent: {format_int(key_information['e'])}")
        print(f"\tprivate exponent: {format_int(key_information['d'])}")
        print(f"\tInverse of q modulus p: {format_int(key_information['iqmp'])}")
        print(f"\tP: {format_int(key_information['p'])}")
        print(f"\tq: {format_int(key_information['q'])}")

    comment, next = get_comment(content, next)

    print(f"Comment: {comment}")

    check_padding(content, next)

def format_int(num: int, max_len: int = 10):
    s = str(num)
    if (len(s) > max_len):
        return s[0:max_len] + "..."
    else:
        return s

def get_header(content: bytes):
    # get header
    header_start = 0
    header_end = 0
    while (content[header_end] != 0):
        header_end += 1 

    header = content[header_start:header_end].decode('utf-8')
    return header, header_end + 1

def get_encryption_cipher(content: bytes, start: int):
    return get_string_with_len(content, start)

def get_kdf(content: bytes, start: int):
    return get_string_with_len(content, start)

def get_number_of_keys(content: bytes, start: int):
    return get_int(content, start)

def get_check_digit(content: bytes, start: int):
    return get_int(content, start)

def get_public_key(content: bytes, start: int):
    # GET key encoding: RSA and DSS -> 4253
    # ECDSA-sha2-* -> rfc 5656
    # ed25519 -> I-D.ietf-curdle-ssh-ed25519
    # mpint defined in 4251 as a 4 byte length with the next x bytes being transformed into the key value.
    key_type, next = get_string_with_len(content, start)

    if (key_type == "ssh-rsa"):
        e, next = get_mpint(content, next)
        n, next = get_mpint(content, next)
        key_info = dict( key_type = key_type, e = e, n = n)
        return key_info, next
    else:
        raise Exception("not Implemented")

def get_private_key(content: bytes, start: int):
    # GET key encoding: RSA and DSS -> 4253
    # ECDSA-sha2-* -> rfc 5656
    # ed25519 -> I-D.ietf-curdle-ssh-ed25519
    # mpint defined in 4251 as a 4 byte length with the next x bytes being transformed into the key value.
    # private key format defined in draft-miller-ssh-agent-04 (https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)
    key_type, next = get_string_with_len(content, start)

    if (key_type == "ssh-rsa"):
        n, next = get_mpint(content, next)
        e, next = get_mpint(content, next)
        d, next = get_mpint(content, next)
        iqmp, next = get_mpint(content, next)
        p, next = get_mpint(content, next)
        q, next = get_mpint(content, next)
        key_info = dict( key_type = key_type, e = e, n = n, d = d, iqmp = iqmp, p = p, q = q)
        return key_info, next
    else:
        raise Exception("not Implemented")
    
def get_comment(content: bytes, start: int):
    return get_string_with_len(content, start)

def check_padding(content:bytes, start: int):
    if (content[start: start + 3] != bytes([0x01, 0x02, 0x03])):
        print(content[start: start + 3])
        raise Exception("Padding is not correct")


#private
def get_string_with_len(content: bytes, start: int):
    str_length, next = get_int(content, start)
    str_start = next
    str_end = next + str_length
    return_string = content[str_start:str_end].decode('utf-8')
    return return_string,str_end

def get_mpint(content: bytes, start: int):
    int_length, next = get_int(content, start)
    int_start = next
    int_end = int_start + int_length
    int_value = int.from_bytes(content[int_start:int_end], byteorder="big")
    return int_value, int_end

def get_int(content: bytes, start: int):
    finish_len = start + 4
    str_length = int.from_bytes(content[start:finish_len])
    return str_length, finish_len
    



if __name__ == "__main__":
    # ssh-keygen -t rsa -b 2048
    # id_rsa_clear
    # no passphrase
    filename = "C:\\Users\\leppa\\.ssh\\id_rsa_clear"

    # ssh-keygen -t rsa -b 4096 
    # id_rsa_clear_2
    # no passphrase
    filename = "C:\\Users\\leppa\\.ssh\\id_rsa_clear_2"
    parseOpenSSHPrivateKeyFile(filename)



# from https://www.openssh.com/specs.html (https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD)

## 1. Overall format
##                       4:
##                       5: The key consists of a header, a list of public keys, and
##                       6: an encrypted list of matching private keys.
##                       7:
##                       8: #define AUTH_MAGIC      "openssh-key-v1"
##                       9:
##                      10:        byte[]  AUTH_MAGIC
##                      11:        string  ciphername
##                      12:        string  kdfname
##                      13:        string  kdfoptions
## 1.3       djm        14:        uint32  number of keys N
## 1.1       markus     15:        string  publickey1
##                      16:        string  publickey2
##                      17:        ...
##                      18:        string  publickeyN
##                      19:        string  encrypted, padded list of private keys
##                      20:
##                      21: 2. KDF options for kdfname "bcrypt"
##                      22:
##                      23: The options:
##                      24:
##                      25:        string salt
##                      26:        uint32 rounds
##                      27:
##                      28: are concatenated and represented as a string.