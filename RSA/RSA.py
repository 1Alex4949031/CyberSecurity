import math
import random
from hashlib import sha256


def sieve_of_eratosthenes(limit):
    """Генерация списка простых чисел до 10000 решетом Эратосфена."""
    primes_init = []
    sieve = [True] * (limit + 1)
    for p in range(2, limit + 1):
        if sieve[p]:
            primes_init.append(p)
            for i in range(p * p, limit + 1, p):
                sieve[i] = False
    return primes_init


primes = sieve_of_eratosthenes(10000)


def bytes_to_blocks(raw_bytes, block_length):
    """
    Фукция, которая преобразует байты в список числовых блоков заданной длины.
    """
    return [int.from_bytes(raw_bytes[i: i + block_length], 'little') for i in range(0, len(raw_bytes), block_length)]


def blocks_to_bytes(blocks):
    """
    Функция, которая преобразует список числовых блоков обратно в байты.
    """
    return bytes().join(block.to_bytes((block.bit_length() + 7) // 8, 'little') for block in blocks)


def is_prime_Miller_Rabin(n, k=128):
    """ Тест Миллера-Рабина - это вероятностный тест, используемый для проверки, является ли данное число простым.
     Он широко применяется в криптографии и других областях,
     где требуется быстро идентифицировать простые числа, особенно большие.
     В отличие от детерминированных методов, тест Миллера-Рабина не гарантирует точность,
     но при достаточном количестве повторений может предоставить очень высокую степень уверенности в простоте числа. """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Проверка, делится ли n на любое из простых чисел до 10000
    for prime in primes:
        if n % prime == 0:
            return False

    # Найти r и s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    # Провести k тестов
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime(bit_size):
    """ Функция, которая генерирует простые числа заданной битовой длины. """
    while True:
        # Генерация случайного числа заданной битовой длины
        prime_candidate = random.getrandbits(bit_size)
        # Установка старшего и младшего битов в 1 (для увеличения вероятности получения простого числа)
        prime_candidate |= (1 << bit_size - 1) | 1
        # Проверка на простоту
        if is_prime_Miller_Rabin(prime_candidate):
            return prime_candidate


def module_power(a, n, m):
    """
    Функция module_power(a, n, m) реализует алгоритм быстрого возведения в степень по модулю.
    Это эффективный способ вычисления a^n mod m, который широко используется в криптографии и других областях вычислений.
    """
    r = 1
    while n > 0:
        if n & 1 == 1:
            r = (r * a) % m
        a = (a * a) % m
        n >>= 1
    return r


def extended_gcd(a, b):
    """
    Функция extended_gcd(a, b) реализует расширенный алгоритм Евклида.
    Этот алгоритм используется не только для нахождения наибольшего общего делителя (НОД) двух чисел a и b,
    но также для вычисления коэффициентов x и y, которые удовлетворяют уравнению Безу.
    """
    x_current, x_previous = 0, 1  # Коэффициенты для 'a'
    y_current, y_previous = 1, 0  # Коэффициенты для 'b'

    while b != 0:
        quotient = a // b
        a, b = b, a - quotient * b
        x_previous, x_current = x_current, x_previous - quotient * x_current
        y_previous, y_current = y_current, y_previous - quotient * y_current

    return x_previous


def RSA_keys_generate(bits):
    """
    Функция RSA_keys_generate(bits) генерирует пару ключей для шифрования RSA.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi - 1)

    while math.gcd(e, phi) != 1:
        e = random.randrange(2, phi - 1)

    d = extended_gcd(e, phi)
    if d < 0:
        d += phi

    return (e, n), (d, n)


def encrypt_decrypt(blocks, key):
    """
    Функция, которая шифрует или расшифровывает список блоков с использованием заданного ключа.
    """
    p, m = key
    return [module_power(block, p, m) for block in blocks]


def encrypt_message(message, public_key):
    """Функция, которая шифрует заданное сообщение публичным ключом."""
    e, n = public_key
    block_length = (n.bit_length() - 1) // 8
    blocks = bytes_to_blocks(message, block_length)
    ciphertext = encrypt_decrypt(blocks, public_key)
    return blocks_to_bytes(ciphertext)


def decrypt_ciphertext(ciphertext, private_key):
    """Функция, которая расшифровывает последовательность битов (зашифрованное сообщение) приватным ключом."""
    d, n = private_key
    block_length = ((n.bit_length() - 1) // 8) + 1
    blocks = bytes_to_blocks(ciphertext, block_length)
    message = encrypt_decrypt(blocks, private_key)
    return blocks_to_bytes(message)


def hash_file(file_name):
    """Шифрование файла алгоритмом SHA256"""
    hasher = sha256()
    with open(file_name, "rb") as file:
        for block in iter(lambda: file.read(hasher.block_size), b''):
            hasher.update(block)
    return hasher.digest()


def sign_file(file_name, private_key):
    """Функция, которая возвращает ЭЦП"""
    return encrypt_message(hash_file(file_name), private_key)


def verify_signature(file_name, signature, public_key):
    """Проверка ЭЦП"""
    print(f'Электронная подпись: {signature}')
    file_hash = hash_file(file_name)
    decrypted_signature = decrypt_ciphertext(signature, public_key)
    if file_hash == decrypted_signature:
        print("Верификация прошла успешно!")
        return True
    print("Верификация не пройдена!")
    return False
