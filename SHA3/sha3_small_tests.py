import hashlib
import unittest

from sha3 import sha3_512
from sha3 import sha3_384
from sha3 import sha3_256
from sha3 import sha3_224


class SmallTestCase(unittest.TestCase):
    def test_small_sha_224(self):
        message = 'hello world'
        actual = sha3_224(message)
        expected = hashlib.sha3_224(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)

    def test_small_sha_256(self):
        message = 'hello world'
        actual = sha3_256(message)
        expected = hashlib.sha3_256(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)

    def test_small_sha_384(self):
        message = 'hello world'
        actual = sha3_384(message)
        expected = hashlib.sha3_384(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)

    def test_small_sha_512(self):
        message = 'hello world'
        actual = sha3_512(message)
        expected = hashlib.sha3_512(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)

    def test_china_sha_224(self):
        message = '你好你好嗎你好你好嗎你好你好嗎'
        actual = sha3_224(message)
        expected = hashlib.sha3_224(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)

    def test_china_sha_512(self):
        message = '你好你好嗎'
        actual = sha3_512(message)
        expected = hashlib.sha3_512(message.encode('utf-8')).hexdigest()
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
