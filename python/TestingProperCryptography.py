import unittest
import ProperCryptography

class TestRandomNumberGeneration(unittest.TestCase):
    c: ProperCryptography.Cryptography

    def __init__(self, methodName: str = "runTest") -> None:
        self.c = ProperCryptography.Cryptography()
        super().__init__(methodName)

    # empty tests

    def testEmptyRandomReturnsBytes(self):
        randbytes = self.c.getRandomNumber()
        self.assertIsInstance(randbytes, bytes)

    def testEmptyRandomReturnsSixteenBytes(self):
        randbytes = self.c.getRandomNumber()
        self.assertEqual(len(randbytes), 16)

    def testEmptyRandomReturnsTwoDifferentSetsOfBytes(self):
        randbytes1 = self.c.getRandomNumber()
        randbytes2 = self.c.getRandomNumber()
        self.assertNotEqual(randbytes1, randbytes2)

    # Number tests
    def testNumberRandomReturnsBytes(self):
        randbytes = self.c.getRandomNumber(2)
        self.assertIsInstance(randbytes, bytes)

    # test a 16 byte array of random bytes and see if the output lengths match for all 16
    def testNumberRandomReturnsNumberBytes(self):
        randbytes = self.c.getRandomNumber()
        for length in randbytes:
            randbytes2 = self.c.getRandomNumber(length)
            self.assertEqual(len(randbytes2), length)

    def testRandomGenerationIsUnique(self):
        randbytes1 = self.c.getRandomNumber(2)
        randbytes2 = self.c.getRandomNumber(2)
        self.assertNotEqual(randbytes1, randbytes2)

    # Non-number tests
    def testNonNumberStringRandomFails(self):
        with self.assertRaises(TypeError):
            randbytes = self.c.getRandomNumber('banana')

    def testNonNumberFloatRandomFails(self):
        with self.assertRaises(TypeError):
            randbytes = self.c.getRandomNumber(1.0)

    def testNonNumberBytesRandomFails(self):
        with self.assertRaises(TypeError):
            randbytes = self.c.getRandomNumber(b'\x00\x50')
    
if __name__ == '__main__':
    unittest.main()