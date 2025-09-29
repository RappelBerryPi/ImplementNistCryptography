import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import bcrypt

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
    elif (kdf_type == "bcrypt"):
        salt, next = get_salt_value(content, next)
        split_salt, next_2 = get_bytes_with_len(salt, 0) 
        rounds, next_2 = get_int(salt, next_2)
        print(f"Salt Value: {split_salt}")
        print(f"rounds?: {rounds}")
        password = input("Enter the password that encrypts this file:")
        password = password.encode('utf-8')
        key_value = bcrypt.kdf(password, split_salt, 48, rounds, True)
    else:
        raise Exception("not Implemented")
    
    num_of_keys, next = get_number_of_keys(content, next)
    print(f"Number of Keys in Private key file: {num_of_keys}")

    public_key_length, next = get_public_key_length(content, next)
    print(f"public Key Length: {public_key_length}")
    
    key_information, next = get_public_key(content, next)
    print(f"public Key type: {key_information['key_type']}")
    if (key_information['key_type'] == "ssh-rsa"):
        print(f"\tpublic exponent: {format_int(key_information['e'])}")
        print(f"\tmodulus: {format_int(key_information['n'])}")

    if (key_information['key_type'].startswith("ecdsa-sha2-") or key_information['key_type'].startswith("sk-ecdsa-sha2-")):
        print(f"\tcurve: {key_information['curve_name']}")
        print(f"\tpublic key (X): {format_int(key_information['point_x'])}")
        print(f"\tpublic key (y): {format_int(key_information['point_y'])}")
    if (key_information['key_type'] == "ssh-ed25519"):
        print(f"\tencoded public key: {key_information['public_key']}")

    private_key_length, next = get_private_key_length(content, next)
    print(f"private_key_length: {private_key_length}")

    if (kdf_type != "none"):
        c = Cipher(algorithms.AES256(key_value[0:32]), modes.CTR(key_value[32:]))
        decryptor = c.decryptor()
        content_2 = decryptor.update(content[next:]) + decryptor.finalize()
        content = content_2
        next = 0

    check_digit, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit}")

    check_digit2, next = get_check_digit(content, next)
    print(f"Check Digit: {check_digit2}")

    print(f"Check Digits match?: {check_digit == check_digit2}")
    if (check_digit != check_digit2):
        raise Exception("Check digits don't match. Error.")

    key_information, next = get_private_key(content, next)
    print(f"Private Key type: {key_information['key_type']}")
    if (key_information['key_type'] == "ssh-rsa"):
        print(f"\tmodulus: {format_int(key_information['n'])}")
        print(f"\tpublic exponent: {format_int(key_information['e'])}")
        print(f"\tprivate exponent: {format_int(key_information['d'])}")
        print(f"\tInverse of q modulus p: {format_int(key_information['iqmp'])}")
        print(f"\tP: {format_int(key_information['p'])}")
        print(f"\tq: {format_int(key_information['q'])}")
    elif (key_information['key_type'].startswith("ecdsa-sha2-")):
        print(f"\tcurve: {key_information['curve_name']}")
        print(f"\tpublic key (X): {format_int(key_information['point_x'])}")
        print(f"\tpublic key (y): {format_int(key_information['point_y'])}")
        print(f"\tprivate key (d): {format_int(key_information['private_key'])}")
    elif (key_information['key_type'] == "ssh-ed25519"):
        print(f"\tencoded public key: {key_information['public_key']}")
        print(f"\tprivate key (d): {format_int(key_information['private_key'])}")
    elif (key_information['key_type'].startswith("sk-ecdsa-sha2-")):
        print(f"\tcurve: {key_information['curve_name']}")
        print(f"\tpublic key (X): {format_int(key_information['point_x'])}")
        print(f"\tpublic key (y): {format_int(key_information['point_y'])}")
        print(f"\id: {key_information['id']}")
        print(f"\other??: {key_information['other']}")
    else:
        raise Exception("not implemented")

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

def get_public_key_length(content: bytes, start: int):
    return get_int(content, start)

def get_private_key_length(content: bytes, start: int):
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
    elif (key_type.startswith("ecdsa-sha2-") or key_type.startswith("sk-ecdsa-sha2-")):
        curve_name, next = get_string_with_len(content, next)
        point, next = get_bytes_with_len(content, next)
        # see https://www.secg.org/sec1-v2.pdf section 2.3.3
        point_len = (len(point) - 1) // 2
        point_x = int.from_bytes(point[1:point_len + 1])
        point_y = int.from_bytes(point[point_len + 1:])
        if (key_type.startswith("sk-ecdsa-sha2-")):
            id, next = get_string_with_len(content, next)
        key_info = dict(key_type = key_type, curve_name = curve_name, point_x = point_x, point_y = point_y)
        return key_info, next
    elif (key_type == "ssh-ed25519"):
        public_key, next = get_bytes_with_len(content, next)
        key_info = dict(key_type = key_type, public_key = public_key)
        return key_info, next
    else:
        print(content[next:])
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
    elif (key_type.startswith("ecdsa-sha2-")):
        curve_name, next = get_string_with_len(content, next)
        point, next = get_bytes_with_len(content, next)
        point_len = (len(point) - 1) // 2
        point_x = int.from_bytes(point[1:point_len + 1])
        point_y = int.from_bytes(point[point_len + 1:])
        private_key, next = get_mpint(content, next)
        key_info = dict( key_type = key_type, point_x = point_x, point_y = point_y, curve_name = curve_name, private_key = private_key)
        return key_info, next
    elif (key_type == "ssh-ed25519"):
        public_key, next = get_bytes_with_len(content, next)
        private_key, next = get_bytes_with_len(content, next)
        private_key_bytes = int.from_bytes(private_key[0:32])
        private_key_public_key = private_key[32:]
        if (public_key != private_key_public_key):
            raise Exception("public key values do not match (see encoding)")
        key_info = dict(key_type = key_type, public_key = public_key, private_key = private_key_bytes)
        return key_info, next
    elif (key_type.startswith("sk-ecdsa-sha2-")):
        curve_name, next = get_string_with_len(content, next)
        point, next = get_bytes_with_len(content, next)
        point_len = (len(point) - 1) // 2
        point_x = int.from_bytes(point[1:point_len + 1])
        point_y = int.from_bytes(point[point_len + 1:])
        id, next = get_string_with_len(content, next)
        constraint_type = content[next]
        next +=1 
        if (constraint_type == 0x01):
            lifetime, next = get_bytes_with_len(content, next)
            print("TODO: ???") #TODO
        next += 4 # skip 4 chars.
        key_info = dict( key_type = key_type, point_x = point_x, point_y = point_y, curve_name = curve_name, id = id, other = lifetime )
        return key_info, next
    else:
        print(content[next:])
        raise Exception("not Implemented")
    
def get_comment(content: bytes, start: int):
    return get_string_with_len(content, start)

def check_padding(content:bytes, start: int):

    len_content = len(content)
    padding_value = 0x01
    while (start < len_content):
        if (content[start] != padding_value):
            raise Exception("Padding is not correct")
        padding_value += 1
        start += 1


def get_salt_value(content: bytes, start: int):
    return get_bytes_with_len(content, start)

def get_rounds_info(content: bytes, start: int):
    return get_int(content, start)    


#private
def get_string_with_len(content: bytes, start: int):
    return_string_bytes, next = get_bytes_with_len(content, start)
    return_string = return_string_bytes.decode('utf-8')
    return return_string, next

def get_bytes_with_len(content: bytes, start: int):
    str_length, next = get_int(content, start)
    str_start = next
    str_end = next + str_length
    return_string = content[str_start:str_end]
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

    # ssh-keygen -t rsa -b 4096 
    # id_rsa_enc
    # "password"
    filename = "C:\\Users\\leppa\\.ssh\\id_rsa_enc"

    # ssh-keygen -t ecdsa -b 256
    # id_ecdsa_clear
    # no passphrase
    filename = "C:\\Users\\leppa\\.ssh\\id_ecdsa_clear"

    # ssh-keygen -t ecdsa -b 256
    # id_ecdsa_enc
    # "password"
    filename = "C:\\Users\\leppa\\.ssh\\id_ecdsa_enc"

    # ssh-keygen -t ecdsa -b 521
    # id_ecdsa_clear_2
    # no passphrase
    filename = "C:\\Users\\leppa\\.ssh\\id_ecdsa_clear_2"

    # ssh-keygen -t ed25519
    # id_ed25519_clear
    # no passphrase
    filename = "C:\\Users\\leppa\\.ssh\\id_ed25519_clear"

    # ssh-keygen -t ed25519
    # id_ed25519_enc
    # "password" 
    filename = "C:\\Users\\leppa\\.ssh\\id_ed25519_enc"

    # ssh-keygen -t ecdsa-sk -b 256
    # id_ecdsa_enc
    # no passphrase 
    filename = "C:\\Users\\leppa\\.ssh\\id_ecdsa_sk_pin"
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