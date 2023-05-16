#!/usr/bin/python3

#from functools import reduce
#from operator import add
import os
import sys

Phrase = 'Now is the time for all great space mathematicians to come out and play'

#
# Verify input is the right size and convertable to a list (comma separated)
def verify_input(phrase_string):

    pstring = phrase_string.upper()
    expected_string = Phrase.upper()
    # msg = f"input:    <{pstring}>\n"
    # msg += f"expected: <{expected_string}>\n"
    # print(msg)
    if pstring == expected_string:
        return True
    else:
        return False

#
# Define challenge, collect input and determine if team input is correct
def challenge():
    msg = f"\n\nWe found a folder in an old file cabinet marked 'OP-20-G'.\n"
    msg += f"On the outside of the folder was written \n"
    msg += f" - To be decrypted.\n"
    msg += f"Decode the last message to obtain your flag.\n"
    msg += f"\nThe messages to decypher are at: 'encrypted_msgs.txt'\n"
    msg += f"We also found a book with a list of word and numbers: 'word_dictionary.json'\n"
    msg += f"\n\nTo recieve your flag enter the plain text of the last message: \n"
    print(msg)

    # Get input from player
    phrase_in = input()
 
    return verify_input(phrase_in)

if __name__ == "__main__":

    if challenge() == True:
        msg = f"\n----------------------------------\n"
        msg += f"Congratulations you got it right!!\n"
        flag = os.getenv('FLAG')
        msg += f"Here is your flag: {flag}\n"
        msg += f"----------------------------------\n"
        print(msg, flush=True)

    else:
        print(f"\nSorry wrong answer, try again.\n", flush=True)

    print(f"--END", flush=True)   
    

