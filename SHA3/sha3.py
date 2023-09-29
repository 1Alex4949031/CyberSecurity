import numpy as np

# Параметры алгоритма
l = 6
w = 64
b = 25 * w

# Предварительно вычисленные значения для битовых сдвигов функции rho
shifts = [[0, 36, 3, 41, 18],
          [1, 44, 10, 45, 2],
          [62, 6, 43, 15, 61],
          [28, 55, 25, 21, 56],
          [27, 20, 39, 8, 14]]

# Предварительно вычисленные значения для округления констант функции iota
RCs = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
       0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
       0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]


def get_bitstring(message):
    """
    Функция принимает строку в качестве аргумента и возвращает битовую строку из заданной.
    :param message: принимаемая строка
    :return: битовая строка
    """
    return ''.join(['{0:08b}'.format(b)[::-1] for b in message.encode('utf-8')]) + '01100000'


def string_to_array(string):
    """
    Данная функция string_to_array преобразует строку из битов (string)
     в трехмерный массив из целых чисел (state_array).
    :param string: строка из битов
    :return: трехмерный массив
    """
    state_array = np.zeros([5, 5, w], dtype=int)
    for x in range(5):
        for y in range(5):
            for z in range(w):
                if (w * (5 * x + y) + z) < len(string):
                    state_array[y][x][z] = int(string[w * (5 * x + y) + z])
    return state_array


def hex_to_array(num):
    """
    Функция преобразует шестнадцатеричное число (num) в массив битов.
    :param num: шестнадцатеричное число
    :return: массив битов
    """
    bitstring = '{0:0{1}b}'.format(num, w)
    return np.array([int(bit) for bit in bitstring])


def pad(rate, message_length):
    """
    Функция pad реализует метод дополнения (padding) для сообщений,
     что часто используется в криптографии и обработке данных.
    :param rate: значение, используется для определения количества нулей,
     которые необходимо добавить к сообщению перед добавлением бита '1'.
    :param message_length: длина
    :return:
    """
    j = (-(message_length + 1)) % rate
    return '0' * j + '1'


def theta(array):
    """
    Функция theta реализует одну из этапных функций, используемых в криптографическом алгоритме Keccak,
     который лежит в основе стандарта хеширования SHA-3.
     Эта функция представляет собой часть процедуры обработки данных в Keccak
     и служит для добавления более сложных структур в процесс.
     Функция theta служит для введения нелинейности и создания связи между различными частями входного массива,
      что повышает уровень криптографической безопасности алгоритма Keccak.
    :param array: входной массив
    :return: модифицированный массив
    """
    array_prime = array.copy()
    C = np.zeros([5, w], dtype=int)
    D = np.zeros([5, w], dtype=int)
    for x in range(5):
        for y in range(5):
            C[x] ^= array[x][y]
    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ np.roll(C[(x + 1) % 5], 1)
    for x in range(5):
        for y in range(5):
            array_prime[x][y] ^= D[x]
    return array_prime


def rho(array):
    """
    Функция rho реализует другую этапную функцию алгоритма Keccak (основы SHA-3).
     Этап rho представляет собой процесс вращения битовых строк.
    :param array: входной массив
    :return: модифицированный массив
    """
    array_prime = array.copy()
    for x in range(5):
        for y in range(5):
            array_prime[x][y] = np.roll(array[x][y], shifts[x][y])
    return array_prime


def pi(array):
    """
    Функция pi реализует ещё одну из этапных функций алгоритма Keccak (который является основой для SHA-3).
     Этап pi служит для переупорядочивания элементов внутри массива.
    :param array: входной массив
    :return: модифицированный массив
    """
    array_prime = array.copy()
    for x in range(5):
        for y in range(5):
            array_prime[x][y] = array[(x + (3 * y)) % 5][x]
    return array_prime


def chi(array):
    """
    Функция chi реализует ещё одну из этапных функций алгоритма Keccak (который является основой для SHA-3).
     Этап chi применяет некоторое нелинейное преобразование к данным.
    :param array: входной массив
    :return: модифицированный массив
    """
    array_prime = np.zeros(array.shape, dtype=int)
    for x in range(5):
        for y in range(5):
            array_prime[x][y] = array[x][y] ^ ((array[(x + 1) % 5][y] ^ 1) & (array[(x + 2) % 5][y]))
    return array_prime


def iota(array, round_index):
    """
    Функция iota реализует еще одну из этапных функций алгоритма Keccak (который служит основой для SHA-3).
     Этап iota предназначен для применения константы (RCs[round_index]) к определенной части данных,
      что зависит от номера текущего раунда алгоритма.
    :param array: входной массив
    :param round_index: индекс текущего раунда
    :return: модифицированный массив
    """
    RC = hex_to_array(RCs[round_index])
    RC = np.flip(RC)
    array_prime = array.copy()
    array_prime[0][0] ^= RC
    return array_prime


def keccak(state):
    """
    Функция keccak реализует основной цикл алгоритма Keccak, который лежит в основе стандарта хеширования SHA-3.
    Описание функции:
        Цикл раундов:
        for round_index in range(24): — Keccak выполняет 24 раунда обработки.
    Для каждого раунда:
        Применение этапных функций:
        theta(state) — применяет этап тета (theta), который добавляет линейное преобразование к состоянию.
        rho(state) — применяет этап ро (rho), который вращает биты в состоянии.
        pi(state) — применяет этап пи (pi), который переупорядочивает биты.
        chi(state) — применяет этап хи (chi), который добавляет нелинейное преобразование.
        iota(state, round_index) — применяет этап йота (iota), который добавляет константу раунда к состоянию.
    Все эти этапы применяются последовательно к текущему состоянию state.
    :param state: текущее состояние
    :return: финальное состояние
    """
    for round_index in range(12 + 2 * l):
        state = iota(chi(pi(rho(theta(state)))), round_index)
    return state


def squeeze(array, bits):
    """
    Функция squeeze выполняет так называемую "выжимку" (squeeze) из массива состояния,
     что является частью процесса хеширования.
    Этот процесс конвертирует внутреннее состояние алгоритма в конечное хеш-значение.
    Описание функции:
        Инициализация начального значения хеша:
            initialHash = '' создает пустую строку, в которую будет записано выходное значение хеша.
        Преобразование состояния в битовую строку и конвертация в hex:
            Во внешних циклах происходит проход по каждому элементу (или "ячейке") двумерного массива array.
            lane = array[j][i] берет текущую ячейку (известную как "lane" в контексте Keccak).
            Следующий блок кода преобразует ячейку в битовую строку string.
            Последующий блок кода разделяет эту битовую строку на байты (по 8 бит),
             переворачивает каждый байт и конвертирует его в шестнадцатеричное значение, добавляя к initialHash.
        Обрезание результата:
        return initialHash[:int(bits / 4)] возвращает только первые (bits / 4) символа из initialHash.
        Это делается для обеспечения того, чтобы конечный хеш имел нужную длину в битах, деленную на 4
         (так как каждый шестнадцатеричный символ представляет 4 бита).
    :param array: входной двумерный массив
    :param bits: длина (в битах) желаемого выходного хеша.
    :return: шестнадцатеричное значение хеша определенной длины.
    """
    initialHash = ''
    for i in range(5):
        for j in range(5):
            lane = array[j][i]
            string = ''
            for m in range(len(lane)):
                string += str(lane[m])
            for n in range(0, len(string), 8):
                byte = string[n:n + 8]
                byte = byte[::-1]
                initialHash += '{0:02x}'.format(int(byte, 2))
    return initialHash[:int(bits / 4)]


def sha3(message, bits):
    """
    Функция sha3 реализует алгоритм хеширования Keccak, который был выбран NIST
     (Национальным институтом стандартов и технологии США) в качестве официального стандарта SHA-3.
    :param message: входное сообщение
    :param bits: длина (в битах) желаемого выходного хеша.
    """
    # Значения capacity и rate, используя bits.
    capacity = 2 * bits
    rate = b - capacity

    # Преобразуем сообщение в битовую строку.
    bitstring = get_bitstring(message)

    # Дополнение битовой строки в соответствии с функцией pad 10*1.
    padded = bitstring + pad(rate, len(bitstring) % rate)

    # Функция sponge поглощает биты <rate> за раунд, так что (len(padded) // rate) общее количество раундов.
    sponge_rounds = len(padded) // rate

    # Инициализируем массив.
    state = np.zeros(b, dtype=int).reshape(5, 5, w)

    # Для каждого раунда sponge поглощайте биты <rate> и обрабатывайте массив состояний перестановкой keccak.
    for i in range(sponge_rounds):
        current_string = padded[(i * rate):(i * rate) + rate]
        array = string_to_array(current_string)
        state = np.bitwise_xor(state, array)
        state = keccak(state)

    # Фаза "выжимки" выводит конечное хэш-значение
    return squeeze(state, bits)


def sha3_224(message):
    """
    SHA3-224 алгоритм.
    :param message: строка, над которой будет применен алгоритм хеширования.
    :return: значение алгоритма хешироваиняю.
    """
    return sha3(message, 224)


def sha3_256(message):
    """
    SHA3-256 алгоритм.
    :param message: строка, над которой будет применен алгоритм хеширования.
    :return: значение алгоритма хешироваиняю.
    """
    return sha3(message, 256)


def sha3_384(message):
    """
    SHA3-384 алгоритм.
    :param message: строка, над которой будет применен алгоритм хеширования.
    :return: значение алгоритма хешироваиняю.
    """
    return sha3(message, 384)


def sha3_512(message):
    """
    SHA3-512 алгоритм.
    :param message: строка, над которой будет применен алгоритм хеширования.
    :return: значение алгоритма хешироваиняю.
    """
    return sha3(message, 512)
