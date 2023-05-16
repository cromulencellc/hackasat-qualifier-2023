#!/usr/bin/env python3

import pickle
import math
import itertools
from multiprocessing import Pool

import sympy
from Cryptodome.PublicKey import RSA
from Cryptodome.Math.Numbers import Integer

FACTOR_SIZE = 512  # Number of bits in each factor. The key size will be approximately 4 times this number.
RSA_EXPONENT = 65537  # e value for RSA


def __pick_prime_with_totient_factors(N, number_of_factors):
    """
    Given a max factor N and a number of factors:
    Return a tuple of a prime p and two lists of factors: (p, [f0, f1, ..., fn], [g0, g1, ..., gn])
    where:
    m = f0*f1*...*fn
    n = g0*g1*...*gn
    p = (m+1)*(n+1)
    p is prime
    all of the factors f0..fn and g0..gn are prime, f0 is always 4, g0 is always 2, and all the factors are less than N
    the number of factors in m and n is number_of_factors
    The factors f1..n and g1..n can be used to factor the totient,
    which will be important when calculating the period (order) of the group later on
    """
    p = 1
    m = 0
    n = 0
    factors_m = list()
    factors_n = list()
    while not sympy.isprime(m + 1):
        factors_m = [4] + [sympy.randprime(2, N) for _ in range(number_of_factors - 1)]  # Setting this to 4 s.t. all
        # periods are even to allow for contestants to skip a step
        m = math.prod(factors_m)

    while sympy.isprime(n + 1) is False:
        factors_n = [2] + [sympy.randprime(2, N) for _ in range(number_of_factors - 1)]
        n = math.prod(factors_n)
        p = (m + 1) * (n + 1)

    assert (m * n // 4 % 2) == 0

    return p, factors_m, factors_n


def __get_keys(factor_size, exponent):
    # m and n will be factors of the totient: they are related to the RSA p and q values by:
    # m = p - 1
    # n = q - 1
    p, m_factors, n_factors = __pick_prime_with_totient_factors(2 ** factor_size, 3)
    m, n = math.prod(m_factors), math.prod(n_factors)
    N = (m + 1) * (n + 1)
    e = exponent
    d = pow(e, -1, int(Integer(m).lcm(Integer(n))))
    return RSA.construct((N, e, d), consistency_check=True).export_key()


def generate_keys(num_keys: int):
    output_keys = []
    for _ in range(num_keys):
        output_keys.append(__get_keys(FACTOR_SIZE, RSA_EXPONENT))
    return output_keys


def main():
    num_cores = 64
    num_keys_per_core = 15
    num_key_files = 60

    # It would be faster to do this with a parallel processor (GPU)
    # but troubleshooting Cuda library errors will take too long,
    # and not everyone will have an Nvidia GPU
    print("Generating " + str(num_cores * num_keys_per_core * num_key_files)
          + " keys in " + str(num_key_files) + " files.")
    for i in range(num_key_files):
        print("Generating key file " + str(i) + "...")
        pool = Pool()
        results = pool.map(generate_keys, [num_keys_per_core] * num_cores)
        results = list(itertools.chain.from_iterable(results))
        with open("keys" + str(i) + ".txt", 'wb') as keys_writer:
            keys_writer.write(pickle.dumps(results))
        print("Key file " + str(i) + " is generated.")


if __name__ == "__main__":
    main()
