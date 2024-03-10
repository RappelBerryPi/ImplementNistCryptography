import secrets

class Cryptography:
    def getRandomNumber(self, length: int = 16):
        if (isinstance(length, int)):
            return secrets.SystemRandom().randbytes(length)
        else:
            raise TypeError("Length isn't type int. Found {}".format(type(length)))

if __name__ == "__main__":
    c = Cryptography()
    print(c.getRandomNumber())