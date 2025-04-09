import os
from cryptography.hazmat.primitives.ciphers import algorithms


if __name__ == "__main__":
    key = os.urandom(32)
    Cipher = algorithms.AES(key)