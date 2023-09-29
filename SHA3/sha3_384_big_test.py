import hashlib
import time
import unittest

from CyberSecurity.generate_string import generate_large_string
from CyberSecurity.sha3 import sha3_384


class BigTestCase(unittest.TestCase):
    def test_large_sha_384(self):
        message = generate_large_string(1)

        start_time = time.time()
        actual = sha3_384(message)
        end_time = time.time()
        act_time = end_time - start_time

        start_time = time.time()
        expected = hashlib.sha3_384(message.encode('utf-8')).hexdigest()
        end_time = time.time()
        exp_time = end_time - start_time

        self.assertEqual(actual, expected)
        print(f"\nСвоя реализация:\nВремя: {act_time}\nРезультат: {actual}\n")
        print('-' * 100)
        print(f"\nЭталонная реализация:\nВремя: {exp_time}\nРезультат: {expected}\n")


if __name__ == '__main__':
    unittest.main()
