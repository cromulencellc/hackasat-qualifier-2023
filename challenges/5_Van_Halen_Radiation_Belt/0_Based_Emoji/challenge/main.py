#!/usr/bin/env python3

from emojis import *
from primes import *
import config as c
import math
import sys
import os
from functools import reduce
import time
import ctf.io
import ctf.timeout

n = get_p() * get_q()


def get_lcm():
    return math.lcm(get_p() - 1, get_q() - 1)


def get_d():
    return pow(c.e, -1, get_lcm())


bits = (c.emoji_base - 1).bit_count()

loop = True


def encrypt(msg):
    m = int.from_bytes(msg.encode('utf-8'), sys.byteorder)
    return pow(m, get_d(), n)


def decrypt(msg):
    return pow(msg, c.e, n)


def slice_numbers(num):
    num_str = bin(num)[2:]
    if (len(num_str) % bits) != 0:
        left_padding = len(num_str) + (bits - (len(num_str) % bits))
        num_str = num_str.zfill(left_padding)
    return [num_str[i:i + bits] for i in range(0, len(num_str), bits)]


def get_factor(emoji):
    if emoji in select_emojis() and len(emoji) == 1 and emoji != select_emojis()[0]:
        result = set()
        num = decode_emoji(emoji)
        num_factors = factors(num)
        for factor in num_factors:
            result.add(select_emojis()[factor])
        return result
    else:
        return None


def factors(num):
    step = 2 if num % 2 else 1
    return set(reduce(list.__add__, ([i, num // i] for i in range(1, int(math.sqrt(num)) + 1, step) if num % i == 0)))

def pprint(s):
    print(s, flush=True)

def menu():
    global loop
    time.sleep(1)
    
    pprint(f"\n\n{printer('Menu')}")
    pprint(f"{printer('Press 1 to get the factors of an emoji')}")
    pprint(f"{printer('Press 2 to get a random prime by bits')}")
    pprint(f"{printer('Press 3 to get the factors of a random number that is at over ' + str(bits) + ' bits in size')}")
    pprint(f"{printer('Press anything else to exit')}")
    
    resp = input()
    if resp == '1⃣':
        pprint(f"{printer('What emoji would you like the factors of?')}")
        em = input()
        if len(em) > 1:
            pprint(f"{printer('Given multiple characters. Defaulting to first character: ')}{em[0]}")
            em = em[0]
        
        if em not in select_emojis():
            pprint(f"{printer('Emoji ')}{em}{printer(' is not valid. Please try again.')} 👎")
        else:
            pprint(f"{printer(get_factor(em))}")
    
    elif resp == '2⃣':
        pprint(f"{printer('How many bits?')}")
        num_bits = input()
        if num_bits in digs:
            num = digs.index(num_bits)
            pprint(f"{printer('Random ' + str(num) + ' -bit prime = ')}"
                  f"{printer(select_emojis()[get_prime_n_bits(num)])}\n")
        else:
            pprint(f"{printer('Please enter a number between 0 - 9')}")
    elif resp == "3⃣":
        pprint(f"{printer('How many bits?')}")
        num_bits = input()
        if num_bits in digs:
            num = digs.index(num_bits)
            if num > bits:
                result = set()
                rand = get_rand_n_bit_num(num)
                num_factors = factors(rand)
                for factor in num_factors:
                    encode = encode_number(factor)
                    result.add(encode)
                pprint(f"{printer(result)}")
            else:
                pprint(f"{printer('Please enter a number between 0 - 9 that is greater than ' + str(bits) + ' bits')}")
        else:
            allowable = ' '.join(str(f) for f in range(bits + 1, 9))
            pprint(f"{printer('Please enter either a ' + allowable + ' or 9')}\n")
    else:
        pprint(f"{printer('Chose an option that does not exist!')}")
        loop = False


def encode_number(num):
    s = ''
    sliced = slice_numbers(num)
    for i in sliced:
        s = s + select_emojis()[int(i, 2)]
    return s


def decode_emoji(emoji_str):
    bin_str = ''
    for em in emoji_str:
        bin_str = bin_str + str(bin(select_emojis().index(em)))[2:].zfill(bits)
    return int(bin_str, 2)


def encode_flag():
    return encode_number(encrypt(c.flag))


pprint(printer("!!! This is a test of the emoji broadcast system !!!"))
pprint(f"{printer('We are using base-')}{printer(str(c.emoji_base))}{printer(' emoji encoding')}")
pprint(f"{printer('That means each emoji represents ' + str(bits) + ' bits')}\n")
pprint(printer("Below is the information needed to solve the challenge\n"))
pprint(f"{printer('N = ')}{encode_number(n)}")
pprint(f"{printer('E = ')}{encode_number(c.e)}\n")
pprint(f"{printer('Here are a few ')}🆓 🐝🐝🐝{printer(' to get you started')}")
pprint(f"{printer('0 = ')}{encode_number(0)}")
pprint(f"{printer('1 = ')}{encode_number(1)}")
pprint(f"{printer('2 = ')}{encode_number(2)}\n")
pprint(f"{printer('To get the ')}🚩{printer(' you must decrypt the')}  🚩")
pprint(f"{'🔐 🚩 👇'}\n")
pprint(f"{printer('C = ')}{encode_flag()}\n")

@ctf.timeout.timeout( 1000 )
def main():
    while loop:
        menu()
        os.system('clear')

# while loop:
#     menu()
#     os.system('clear')

# pprint(printer("Goodbye!"))


if __name__ == "__main__":
    try:
        main() 
    except ctf.timeout.TimeoutError:
        ctf.io.outputStr("Timeout")

    pprint(printer("Goodbye!"))