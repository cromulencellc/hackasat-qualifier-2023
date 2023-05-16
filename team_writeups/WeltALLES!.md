In the Based Emoji challenge, we were tasked with creating a mapping of emoji to binary. Each emoji represented 5 bits, and we were provided with mappings for the emojis 0, 1, and 2. We could also request factors of emojis, random prime numbers with up to 5 bits, and factors of a random integer with 6 to 9 bits.

To solve the challenge, we used the z3 solver to generate a single mapping that satisfied all the requested values. Once we had the mapping, we were given an n, e, and c to verify the signature c and obtain the flag.

The challenge tested our ability to use a solver to generate a mapping that satisfied specific constraints, as well as our knowledge of prime numbers and factorization. The use of emojis added an element of fun and made the challenge engaging.