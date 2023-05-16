#!/usr/bin/env python3

import argparse
import random
import sys
import time
import math
import base64
import re
import pickle
import logging
from datetime import timedelta

import ctf.timeout as TO
import ctf.challenge as Challenge
import ctf.io as IO
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Math.Numbers import Integer

# Resources:
# https://quantum-computing.ibm.com/composer/docs/iqx/guide/shors-algorithm
# https://en.wikipedia.org/wiki/Shor's_algorithm

RSA_EXPONENT = 65537  # e value for RSA
PORT_ENV = 'CHAL_PORT'
HOST_ENV = 'CHAL_HOST'
TIMER = 3 * 60
FLAG: str = Challenge.Challenge().getFlag()


class KeyList:
    def __init__(self, file_name):
        with open(file_name, 'rb') as key_file:
            self.keys_bytes: list[bytes] = pickle.loads(key_file.read())
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.keys_bytes):
            curr_index = self.index
            self.index += 1
            return RSA.import_key(self.keys_bytes[curr_index])
        else:
            raise StopIteration

    def __getitem__(self, item: int):
        return RSA.import_key(self.keys_bytes[item])

    def __len__(self):
        return len(self.keys_bytes)

    def rand_key(self) -> RSA.RsaKey:
        self.index = random.randint(0, len(self.keys_bytes))
        return RSA.import_key(self.keys_bytes[self.index])


def get_period(private_key, alpha):
    period = (private_key.p - 1) * (private_key.q - 1)
    if pow(alpha, period // 4, private_key.n) == 1 and ((period // 2) % 2 == 0):
        period = period // 4
    if pow(alpha, period // 2, private_key.n) == 1 and ((period // 2) % 2 == 0):
        period = period // 2

    assert ((period % 2) == 0)
    assert (pow(alpha, period, private_key.n) == 1)
    factor1 = math.gcd(pow(alpha, period // 2, private_key.n) + 1, private_key.n)
    assert ((private_key.n % factor1) == 0)

    return period


def __challenge_load(private_key: RSA.RsaKey, suppress_print: bool = False):
    if not suppress_print:
        IO.outputStr("Loading challenge, please wait...")
    aes_256_key = get_random_bytes(32)
    aes_256 = AES.new(aes_256_key, AES.MODE_GCM)
    ciphertext, mac = aes_256.encrypt_and_digest(FLAG.encode('UTF-8'))
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_256_key)

    encrypted_message: bytes = base64.b64encode(encrypted_aes_key + aes_256.nonce + mac + ciphertext)
    encrypted_message_pretty = re.sub("(.{64})", "\\1\n", encrypted_message.decode(), 0, re.DOTALL)

    if not suppress_print:
        logging.debug(f'N: {private_key.n}')
        logging.debug("encrypted_aes_key: " + str(len(encrypted_aes_key)) + ", " + str(encrypted_aes_key))
        logging.debug("aes_256.nonce: " + str(len(aes_256.nonce)) + ", " + str(aes_256.nonce))
        logging.debug("mac: " + str(len(mac)) + ", " + str(mac))
        logging.debug("ciphertext: " + str(len(ciphertext)) + ", " + str(ciphertext))

        new_aes_256_key = cipher_rsa.decrypt(encrypted_aes_key)
        assert new_aes_256_key == aes_256_key
        logging.debug("Private key decryption is successful: the keys were correctly generated")

        IO.outputStr(f"""We've intercepted a critical communication between Earth and a satellite. 
Unfortunately, it's encrypted with what we think is a combination of a  
common asymmetric key algorithm and a symmetric encryption algorithm. We have the 
public key used by the satellite but are missing the private key. Fortunately, 
we have a brand new quantum computer that just came online that might be useful.

Your task is to decrypt the communication using our quantum computer. The quantum 
computer doesn't do all the work for you: if you give it the key and an arbitrary 
number, it gives you a value called the period. That's useful for finding the key, 
but you still have to perform some calculations to factor the key and decrypt the 
message.

To interact with the quantum computer, it will prompt you for a modulus and a value 
"a". Given these two values, the quantum computer will calculate the quantum period 
and return it to you. You must then decrypt the message and turn that message in.

The encrypted message we intercepted is: 
{encrypted_message_pretty}

The public key is:
{private_key.public_key().export_key().decode()}

The format of the intercepted message is: 
[AES-256-GCM key encrypted with RSA PKCS#1 OAEP, {str(len(encrypted_aes_key))} bytes] + 
[AES nonce, {str(len(aes_256.nonce))} bytes] + 
[AES-GCM MAC, {str(len(mac))} bytes] + 
[ciphertext, {str(len(ciphertext))} bytes]
""")
    return encrypted_message


def tester(file_name):
    info_report_num = 1000  # Every num keys, logging.info will be issued.
    logging.debug("Loading keys...")
    keys = KeyList(file_name)
    logging.info("Loaded " + str(len(keys)) + " keys. Beginning key testing. Depending on the size of the key file, "
                                              "testing may take a long time.")
    start_time = time.time()
    for key_index, private_key in enumerate(keys):
        encrypted_message = __challenge_load(private_key, suppress_print=True)
        logging.debug("Loaded key at index " + str(key_index))

        bad_alpha = True
        while bad_alpha:
            alpha = random.randint(1, private_key.n)
            period = get_period(private_key, alpha)
            p = math.gcd(pow(alpha, period // 2, private_key.n) - 1, private_key.n)
            q = math.gcd(pow(alpha, period // 2, private_key.n) + 1, private_key.n)
            if p * q == private_key.n and p != 1 and q != 1:
                bad_alpha = False
            else:
                logging.debug("Regenerating alpha for key index " + str(key_index))

        logging.debug("Quantum magic completed for key index " + str(key_index))
        n = p * q  # Some static analyzers will highlight these variables as unassigned; ignore
        e = RSA_EXPONENT
        try:
            d = pow(RSA_EXPONENT, -1, int(Integer(p - 1).lcm(Integer(q - 1))))  # Some static analyzers will complain
            #                                                                      that Integer does not take args;
            #                                                                      ignore
        except ValueError:
            logging.error("Unable to generate private key primitive `d` for key index " + str(key_index)
                          + ".\np: " + str(p)
                          + "\nq: " + str(q))
            continue

        try:
            derived_private_key = RSA.construct((n, e, d), consistency_check=True)
        except ValueError:
            logging.error("Unable to generate private key for key index " + str(key_index) + ". Skipping this key.")
            continue
        else:
            logging.debug("Private key generated for key index " + str(key_index))

        encrypted_message = base64.b64decode(encrypted_message)
        rsa_size = derived_private_key.size_in_bytes()

        enc_aes_key = encrypted_message[0:rsa_size]
        nonce = encrypted_message[rsa_size:rsa_size + 16]
        tag = encrypted_message[rsa_size + 16: rsa_size + 32]
        ciphertext = encrypted_message[rsa_size + 32:]

        cipher_rsa = PKCS1_OAEP.new(derived_private_key)
        try:
            aes_key = cipher_rsa.decrypt(enc_aes_key)
        except ValueError:
            logging.error("Unable to decrypt AES key using PKCS#1 OAEP for key index " + str(key_index) +
                          ". Skipping this key.")
            continue
        else:
            logging.debug("AES key decrypted for key index " + str(key_index))

        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce)

        try:
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            logging.error("Unable to decrypt flag using AES-256-GCM for key index " + str(key_index) +
                          ". Skipping this key.")
            continue
        else:
            logging.debug("Flag decrypted for key index " + str(key_index))

        if plaintext == FLAG.encode("UTF-8"):
            logging.debug("Challenge solved successfully for key index " + str(key_index))
            if key_index > 0 and (key_index + 1) % info_report_num == 0:
                # Doing + 1's here because key_index 0 is the first key, key_index 1 is the second, so on
                curr_time = time.time()
                time_passed = curr_time - start_time
                avg_time_per_key = time_passed / (key_index + 1)
                est_time_left = avg_time_per_key * (len(keys) - key_index - 1)
                logging.info(str(key_index + 1) + " keys tested. Time passed so far: " +
                             str(timedelta(seconds=time_passed)) +
                             ". Avg time/key: " + str(timedelta(seconds=avg_time_per_key)) +
                             ". Estimated time left: " + str(timedelta(seconds=est_time_left)))
        else:
            logging.error("All steps succeeded, but flag does not match for key index " + str(key_index)
                          + "\nExpected flag: " + str(FLAG)
                          + "\nPlaintext:     " + str(plaintext))
    curr_time = time.time()
    time_passed = curr_time - start_time
    logging.info("Finished testing keys. If no errors occurred, then all keys were tested successfully. Total time: " +
                 str(timedelta(seconds=time_passed)))


@TO.timeout(TIMER)
def challenge(file_name, key_index: int):
    if key_index == -1:  # Default value picks a random key
        private_key = KeyList(file_name).rand_key()
    else:  # This option is used for debugging
        try:
            private_key = KeyList(file_name)[key_index]
        except IndexError:
            IO.outputStr("Key index " + str(key_index) + " is out of range.")
            sys.exit(1)
    __challenge_load(private_key)
    while True:
        try:
            modulus_value = IO.input_int("Please enter a modulus for the quantum calculation: ")
        except IO.IoError:
            IO.outputStr("Please enter a value in base 10")
            continue  # "continue" is used as opposed to "pass" so that the loop is restarted

        if modulus_value != private_key.n:
            IO.outputStr("Modulus does not match the public key. Please try again.")
            continue  # "continue" is used as opposed to "pass" so that the loop is restarted

        try:
            alpha = IO.input_int("Please enter an arbitrary value a for the quantum calculations: ")
        except ValueError:
            IO.outputStr("Please enter a value in base 10")
            continue

        period = get_period(private_key, alpha)
        IO.outputStr("\nQuantum computer running...")
        time.sleep(1)
        IO.outputStr("The quantum computer returned the following value for the period:")
        IO.outputStr(f"{period}")


def main():
    parser = argparse.ArgumentParser(
        description="Quantum cryptography challenge for Hack-a-Sat 4 Qualifiers. Developed by Nicholas Cohen and "
                    "Henry Reed @ Cyber and Advanced Platforms Subdivison, The Aerospace Corporation"
    )
    parser.add_argument('--key-file',
                        action='store',
                        help='Point to a specific key file instead of the default "keys.txt"',
                        required=False,
                        default='./keys.txt',
                        type=str)
    parser.add_argument('--test',
                        action='store_true',
                        help='Runs a solver on every single key within the key file. Used for debugging key '
                             'generation and solution.',
                        required=False,
                        default=False)

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Prints debugging logs to STDERR',
                        required=False,
                        default=False)
    parser.add_argument('--key-index',
                        action='store',
                        help='Give a specific key to run the challenge with. Used for debugging and testing the '
                             'solver.',
                        required=False,
                        default=-1,
                        type=int)

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.test:
        tester(args.key_file)
    else:
        try:
            challenge(args.key_file, args.key_index)
        except TO.TimeoutError:
            IO.outputStr("\n\nTimeout --- bye\n\n")
        except KeyboardInterrupt:
            IO.outputStr("\n\nKeyboard Interrupt --- bye\n\n")


if __name__ == "__main__":
    main()
