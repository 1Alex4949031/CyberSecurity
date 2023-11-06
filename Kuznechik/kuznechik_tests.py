import unittest
from gostcrypto.gostcipher import gost_34_12_2015

from kuznechik import kuznyechik_encrypt, kuznyechik_decrypt, kuznyechik_with_small_file, kuznyechik_with_big_file


class KuznechikTests(unittest.TestCase):
    def test_correctness(self):
        # Исходные данные и ключ в шестнадцатеричном виде
        plaintext_hex = "1122334455667700ffeeddccbbaa9988"
        key_hex = '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'

        # Преобразование исходных данных и ключа из шестнадцатеричной строки в целое число
        plaintext = int(plaintext_hex, 16)
        key = int(key_hex, 16)

        # Шифрование со своей реализованной функции
        actual_encrypted = kuznyechik_encrypt(plaintext, key)

        # Преобразование ключа из шестнадцатеричной строки в байты
        key_bytes = bytes.fromhex(key_hex)

        # Создание экземпляра класса Кузнечик с заданным ключом
        cipher = gost_34_12_2015.GOST34122015Kuznechik(bytearray(key_bytes))

        # Шифрование исходных данных, преобразованных в байты (готовая функция)
        expected_encrypted_bytes = cipher.encrypt(bytearray.fromhex(plaintext_hex))

        # Преобразование результата шифрования обратно в целое число
        expected_encrypted = int.from_bytes(expected_encrypted_bytes, 'big')

        # Деширование со своей реализованной функции
        actual_decrypted = kuznyechik_decrypt(actual_encrypted, key)

        # Дефрование исходных данных, преобразованных в байты (готовая функция)
        expected_decrypted_bytes = cipher.decrypt(expected_encrypted_bytes)

        # Преобразование результата дешифрования обратно в целое число
        expected_decrypted = int.from_bytes(expected_decrypted_bytes, 'big')

        # Сравнение результатов шифрования и дешифрования
        self.assertEqual(actual_encrypted, expected_encrypted)
        self.assertEqual(actual_decrypted, expected_decrypted)

    def test_small_file(self):
        kuznyechik_with_small_file("test_small.txt")

    def test_blocks_file(self):
        kuznyechik_with_small_file("test_blocks.txt")

    def test_big_file(self):
        kuznyechik_with_big_file("test_big.txt")


if __name__ == '__main__':
    unittest.main()
