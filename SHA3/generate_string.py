import random
import string


def generate_large_string(size):
    """
    Функция, которая генерирует строку фиксированным размером (> size МБ).
    :param size: размер МБ
    :return: созданная строка
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(size * 1024 * 1025))
