#!/usr/bin/env python3

from pwn import *

import math
import os
import random
import socket
import sys
import base64
import ctf.io as IO
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Math.Numbers import Integer

# Resources:
# https://quantum-computing.ibm.com/composer/docs/iqx/guide/shors-algorithm
# https://en.wikipedia.org/wiki/Shor's_algorithm

RSA_EXPONENT = 65537  # e value for RSA
PORT_ENV = 'CHAL_PORT'
HOST_ENV = 'CHAL_HOST'

# Input validation for environment variables
host = os.getenv(HOST_ENV)
if not host:
    IO.outputStr("Please set the " + HOST_ENV + " environment variable.")
    sys.exit(1)

try:
    port = int(os.getenv(PORT_ENV))
except ValueError:
    IO.outputStr("Please use a valid integer for the " + PORT_ENV + " environment variable.")
    sys.exit(1)
else:
    if not port:
        IO.outputStr("Please set the " + PORT_ENV + " environment variable.")
        sys.exit(1)
    if not 0 < port < 65536:
        IO.outputStr("Please use a valid port range for the " + PORT_ENV + " environment variable.")
        sys.exit(1)

# Solving challenge
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# get ticket from environment
ticket = os.getenv("TICKET")
if ticket:
    prompt = s.recv(128)  # "Ticket please:"
    s.send((ticket + "\n").encode("utf-8"))

s.recv(4096)  # This is the "Please wait" message, which we are ignoring
initial = s.recv(4096)  # Initial message with message description, ciphertext and its portions

# Derive public key and ciphertext component lengths
public_key_text = initial.split(b'The public key is:\n')[1].split(b'\n\nThe format of the intercepted')[0]
public_key = RSA.import_key(public_key_text)
enc_aes_key_len = public_key.size_in_bytes()
modulus = public_key.n

# Derive ciphertext components
key_and_ciphertext_b64 = initial.split(b'we intercepted is: \n')[1].split(b'\n\n')[0].replace(b'\n', b'')
key_and_ciphertext = base64.b64decode(key_and_ciphertext_b64)

# The keys we have generated are ~2048, +/- a few bits. We have to account for this variability by deriving its length
# from the public key
enc_aes_key = key_and_ciphertext[:enc_aes_key_len]
nonce = key_and_ciphertext[enc_aes_key_len:enc_aes_key_len + 16]
tag = key_and_ciphertext[enc_aes_key_len + 16:enc_aes_key_len + 32]
ciphertext = key_and_ciphertext[enc_aes_key_len + 32:]

# This loop is necessary as the alpha we pick is random. The challenge was designed s.t. this loop would not have to be
# utilized too much.
bad_alpha = True
while bad_alpha:
    s.send(str(modulus).encode("UTF-8") + b'\n')
    s.recv(1024)  # Receive second prompt
    alpha = random.randint(1, modulus)
    s.send(str(alpha).encode("UTF-8") + b'\n')
    s.recv(1024)  # "Quantum computer running..."
    period = int(s.recv(1024).split(b'period:\n')[1].split(b"\nPlease")[0])
    p = math.gcd(pow(alpha, period // 2, modulus) - 1, modulus)
    q = math.gcd(pow(alpha, period // 2, modulus) + 1, modulus)
    if p * q == modulus and p != 1 and q != 1:
        bad_alpha = False  # At this point, the challenge is "complete." All that is left to do is basic decryption.

n = p * q  # The n derived here is identical to the n (AKA modulus) from the public key
assert n == modulus  # Verifying that the above comment is true. This should never fail.
e = RSA_EXPONENT
d = pow(RSA_EXPONENT, -1, int(Integer(p - 1).lcm(Integer(q - 1))))
derived_private_key = RSA.construct((n, e, d), consistency_check=True)

cipher_rsa = PKCS1_OAEP.new(derived_private_key)
aes_key = cipher_rsa.decrypt(enc_aes_key)  # If assert passes, this should never fail.
cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)  # If assert passes, this should never fail.
print(plaintext)  # Flag!

