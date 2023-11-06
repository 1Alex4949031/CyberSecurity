import os
import random

# Определите символы, допустимые в шестнадцатеричной системе
hex_digits = '0123456789abcdef'

file_size = 1024 * 1024
# Генерируйте случайные шестнадцатеричные символы
hex_string = ''.join(random.choice(hex_digits) for _ in range(file_size))

# Путь к файлу
file_path = 'test_big.txt'

# Запись строки в текстовый файл
with open(file_path, 'w') as file:
    file.write(hex_string)

print(f"Создан файл: {file_path}")
print(f"Размер файла: {os.path.getsize(file_path)} байт")