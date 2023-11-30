import unittest

import rsa

from RSA import RSA_keys_generate, encrypt_decrypt, sign_file, verify_signature


class RSATests(unittest.TestCase):
    def test_RSA_string_128(self):
        bits = 128
        public, private = RSA_keys_generate(bits)
        print(f'{public} - public key, {private} - private key')
        message = list("Hello world!".encode('utf-8'))
        encrypted_message = encrypt_decrypt(message, public)
        decrypted_message = encrypt_decrypt(encrypted_message, private)
        self.assertEqual(message, decrypted_message)

    def test_RSA_string_256(self):
        bits = 256
        public, private = RSA_keys_generate(bits)
        print(f'{public} - public key, {private} - private key')
        message = list("Hello world!".encode('utf-8'))
        encrypted_message = encrypt_decrypt(message, public)
        decrypted_message = encrypt_decrypt(encrypted_message, private)
        self.assertEqual(message, decrypted_message)

    def test_RSA_correctness_128(self):
        bits = 128
        public, private = RSA_keys_generate(bits)
        print(f'{public} - public key, {private} - private key')
        message = "Hello world!".encode('utf-8')

        encrypted_message_actual = encrypt_decrypt(message, public)
        decrypted_message_actual = encrypt_decrypt(encrypted_message_actual, private)

        # Использование библиотеки rsa
        encrypted_message_expected = [rsa.core.encrypt_int(number, public[0], public[1]) for number in message]
        decrypted_message_expected = [rsa.core.decrypt_int(number, private[0], private[1]) for number in
                                      encrypted_message_actual]

        self.assertEqual(encrypted_message_actual, encrypted_message_expected)
        self.assertEqual(decrypted_message_actual, decrypted_message_expected)

    def test_RSA_correctness_256(self):
        bits = 256
        public, private = RSA_keys_generate(bits)
        print(f'{public} - public key, {private} - private key')
        message = "Hello world!".encode('utf-8')

        encrypted_message_actual = encrypt_decrypt(message, public)
        decrypted_message_actual = encrypt_decrypt(encrypted_message_actual, private)

        # Использование библиотеки rsa
        encrypted_message_expected = [rsa.core.encrypt_int(number, public[0], public[1]) for number in message]
        decrypted_message_expected = [rsa.core.decrypt_int(number, private[0], private[1]) for number in
                                      encrypted_message_actual]

        self.assertEqual(encrypted_message_actual, encrypted_message_expected)
        self.assertEqual(decrypted_message_actual, decrypted_message_expected)

    def test_large_data(self):
        public_key, private_key = RSA_keys_generate(1024)
        signature = sign_file("BigFile.bin", private_key)
        self.assertEqual(verify_signature("BigFile.bin", signature, public_key), True)


if __name__ == '__main__':
    unittest.main()
