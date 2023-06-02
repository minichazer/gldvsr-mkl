"""
Описание работы криптосистемы Гольдвассера - Микали
Криптосистема с открытым ключом, её стойкость основана на задаче различения квадратов и псевдоквадратов.
n = p * q - число RSA
z принадлежит кольцу псевдоквадратов ~Q(n)
Пара чисел n и z - открытый ключ (шифрование)
Пара чисел p и q - секретный ключ (расшифрование)

ШИФРОВАНИЕ:
x - открытый текст = x1, x2, ..., xt - битовая строка 
для всех i принадлежащих [1, ..., t] 
yi = (z^xi * ai^2) mod n, где ai - случайное одноразовое число из Zn
y = (y1, ..., yt) - шифртекст

РАСШИФРОВАНИЕ:
для всех i принадлежащих [1, ..., t]
xi = 0, если (yi / p) = 1,
     1, если (yi / p) = -1

Заметим, что при xi = 0, yi - квадрат
                 xi = 1, yi - псевдоквадрат
Тогда при рассмотрении требуется определить - является ли yi - квадратом или псевдоквадратом.
"""


import random
from constants import first_primes_list
import re
import math

# алгоритм из Algorithmic Number Theory by Bach and Shalli
def jacobi(a: int, p: int):
    """
    Вычисление символа Лежандра (a/p)
    """
    # 2 свойство
    a %= p
    assert p > a > 0 and p % 2 == 1
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = p % 8
            # 7 свойство
            if r == 3 or r == 5:
                t = -t
        # 8 свойство
        a, p = p, a
        # 4 свойство
        if a % 4 == p % 4 == 3:
            t = -t
        a %= p
    if p == 1:
        return t
    else:
        return 0


def generate_pseudo_square(n: int, p: int, q: int):
    """
    Генерация случайного числа из кольца псевдослучайных чисел ~Q(n)
    """
    while True:
        a = random.randint(2, n - 1)
        if jacobi(a, p) == jacobi(a, q) == -1 and jacobi(a, n) == 1:
            return a


def get_lowlevel_prime(n: int):
    """
    Генерация простого числа, которое не делится на первые простые делители
    """
    while True:
        pc = random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor ** 2 <= pc:
                break
        else:
            return pc


def test_MillerRabin(candidate: int):
    """
    Тест Миллера-Рабина, проверяющий число на простоту
    """
    # максимальное количество степеней двойки
    max_2_pow = 0

    # ес - основное число теста; разложение candidate-1 в виде
    # произведения степеней двойки (max_2_pow) на нечётное ec
    ec = candidate - 1
    while ec % 2 == 0:
        ec >>= 1
        max_2_pow += 1

    # проверка правильность разложения
    assert 2 ** max_2_pow * ec == candidate - 1

    # проверка на составность
    def is_composite(round_tester: int):
        if pow(round_tester, ec, candidate) == 1:
            return False
        for i in range(max_2_pow):
            if pow(round_tester, 2 ** i * ec, candidate) == candidate - 1:
                return False
        return True

    # 20 проверок  (точность)
    number_trials = 20
    for i in range(number_trials):
        round_tester = random.randrange(2, candidate)
        if is_composite(round_tester):
            return False
    return True


def get_prime(l: int):
    """
    Получения простого числа длиной l бит, проверяемого Тестом Миллера-Рабина на простоту
    """
    prime_candidate = get_lowlevel_prime(prime_len)
    while not test_MillerRabin(prime_candidate):
        prime_candidate = get_lowlevel_prime(prime_len)
    return prime_candidate


if __name__ == "__main__":

    prime_len = 1024
    p = get_prime(prime_len)
    q = get_prime(prime_len)
    plain_text = "An example of Goldwasser-Micali cryptosystem."  # исходный текст
    n = p * q  # число RSA

    z = generate_pseudo_square(1357, 23, 59)  # z принадлежит кольцу псевдоквадратов ~Q(n)
    print(f"Число p:{p}\nЧисло q:{q}\nЧисло n = p * q: {p*q}\nДля данных p, q, n, число z из кольца ~Q(n) будет равно {z}.")

    binary_text = f"".join("{0:08b}".format(ord(x), "b") for x in plain_text)
    print(f"\nТекст в двоичной системе:\n{binary_text}")

    # ШИФРОВАНИЕ
    encrypted_text = []
    for xi in binary_text:
        # print(bin(z)[2:])
        bin_z = int(bin(z)[2:], 2)
        bin_xi = int(xi)
        rand_a_Zn = int(bin(random.randint(1, n) ** 2)[2:], 2)

        yi = ((bin_z ** bin_xi) * rand_a_Zn) % n
        # print(f"yi: {bin(yi)[2:]}")
        encrypted_text.append(yi)
    print(f"\nЗашифрованный текст: {encrypted_text}")

    # РАСШИФРОВАНИЕ
    decrypted_text = ""
    for i in encrypted_text:
        if jacobi(i, p) == 1:
            decrypted_text += "0"
        elif jacobi(i, p) == -1:
            decrypted_text += "1"
    print(f"\nРасшифрованный текст (бинарный): {decrypted_text}")

    decrypted_text_lst = re.findall("........", decrypted_text)
    print(f"\nОтформатируем по байтам: {decrypted_text_lst}")

    decrypted_text_utf = [int(i, 2) for i in decrypted_text_lst]
    print(f"\nПереведём из байт в десятичное представлние: {decrypted_text_utf}")

    decrypted_text_ascii = [chr(i) for i in decrypted_text_utf]
    print(f"\nПереведём из десятичного в строковое представление: {decrypted_text_ascii}")

    result = "".join(decrypted_text_ascii)
    print(f"\nРезультат расшифрования: {result}")

    print(f"Исходный текст (для сравнения): {plain_text}")

    # # Z*(p-1)
    # Z = [i for i in range(106)]
    # new_Z = []
    # for i in Z:
    #     if math.gcd(i, 106) == 1:
    #         new_Z.append(i)

    # print(len(new_Z))
    # print(f"Z: {new_Z}")

