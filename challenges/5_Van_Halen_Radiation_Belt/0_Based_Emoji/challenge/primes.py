from Crypto.Util.number import *
from random import *
import config as c


def get_prime_n_bits(num_bits):
    return getPrime(num_bits)


def get_rand_n_bit_num(num_bits):
    return getRandomNBitInteger(num_bits)


def get_p():
    return getStrongPrime(c.encryption_bit_size, c.e, randfunc=Random(c.seed).randbytes)


def get_q():
    return getStrongPrime(c.encryption_bit_size, c.e, randfunc=Random(c.seed + 1).randbytes)
