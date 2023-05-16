import json
from operator import itemgetter
from math import sqrt
import argparse
import sys
import os
from pwn import *

context.log_level = 'debug'

START_KEY = 10000
MAX_KEY = 99999

VERBOSE = False

#indexes into possible cg list
KEYI = 0
CGI  = 1
WRDI = 2

def printit(prtstring):
    if VERBOSE:
        print(prtstring, flush=True)


def read_codegroups(fn):
    cgfile = open (fn, "r")
    codegroupdict = json.load(cgfile)
    return codegroupdict


def read_msgs(fn):
    msglist = list()
    msgfile = open(fn,"r")
    for msg in msgfile:
        sublist = list()
        code_list = msg.strip("[], \n'")
        code_list = code_list.split(" ")
        for codegroup in code_list:
            codegroup = codegroup.strip("[], \n'")
            sublist.append(codegroup)
        msglist.append(sublist)
    return msglist


def do_decrypt(encrypted_code, key):
    decrypted_str = ''
    sub_key = str(key)
    for e in range(len(encrypted_code)):
        dc = (int(encrypted_code[e])-int(sub_key[e])) % 10
        decrypted_str = decrypted_str + str(dc)
    return decrypted_str 


def is_prime_num(n):
    if(n > 1):
        for i in range(2, int(sqrt(n)) + 1):
            if (n % i == 0):
                return False
    else:
        return False
    return True


def next_prime(curr):
    while curr < MAX_KEY:
        curr += 1
        if is_prime_num(curr):
            break
    if curr >= MAX_KEY:
        return 0
    return curr


def find_keys(enc_cg, word_dict):
    keylist = list()
    possible_key = START_KEY
    fail_count = 0
    pass_count = 0
    possible_key = next_prime(possible_key)
    while possible_key != 0:
        de_cg = do_decrypt(enc_cg, possible_key)

        # check if the decoded cg from the possible_key is
        # a dictionary item, if it is save it
        if word_dict.get(de_cg) != None:
            keylist.append([possible_key, de_cg, word_dict.get(de_cg)])
            pass_count += 1


        possible_key = next_prime(possible_key)

    keylist.sort()
    return keylist


def main(args):
    printit(f"Read in the list of encrypted messages from {args.msgs}.")
    msg_list = read_msgs(args.msgs)
    printit(f"Read the code group/word dictionary book from {args.dict}.")
    word_dict = read_codegroups(args.dict)
    printit(f"Number of words in dictionary: {len(word_dict)}")

    printit(f"\nA major deviation from JN-25 is that the key book values are in")
    printit(f"  numeric order and they are all prime numbers between 10000 and 99999.")

    printit(f"\nBuild list with all encrypted code groups from the messages.")
    printit(f"  Using all possible keys compare decoded code group with dictionary")
    printit(f"  save valid computed code groups to dictionary as list of possible ")
    printit(f"  solutions.")
    printit(f"This can take a couple of minutes...")
 
    keyList = list()

    # for every encypted word in every message compute all of the possible keys
    # that can result in a dictionary word
    for msg in msg_list:
        msgKeyList = list()
        for ecg in msg:
            ecglist = find_keys(ecg, word_dict)
            msgKeyList.append(ecglist)
        keyList.append(msgKeyList)

    psblkeys = list()
    # across messages filter out all possible keys that are not unique, leaving only
    # hopefully a single key
    for msgpos in range(len(msg_list[0])):
        keys = list()
        # loop through every encrypted message
        for idx in range(len(msg_list)):
            msg = keyList[idx][msgpos]
            # save every 
            for m in msg:
                key = m[0]
                keys.append(key)

            if idx > 0:
                # remove all unique key entries from the list
                keys = list(set(i for i in keys if keys.count(i) > 1))
                keys.sort()
        psblkeys.append(keys)

    computedkeys = list()
    for idx in range(len(psblkeys)):
        if len(psblkeys[idx]) == 1:
            computedkeys.append(psblkeys[idx][0])
        else:
            keyfound = False
            for k in psblkeys[idx]:
                for val in computedkeys:
                    if k > val:
                        computedkeys.append(k)
                        keyfound = True
                        break
                if keyfound:
                    break

    # Look up the keys to build text for each message
    printit(f"\n--------------\nComputed Keys: {computedkeys}")
    printit(f"  (notice that the keys are all prime and in sequence)")
    printit(f"--------------")
    for msgidx in range(len(msg_list)):
        printit(f"Message #{msgidx+1}")
        message = ''
        for idx in range(len(msg_list[0])):
            keylst = computedkeys[idx]
           # print(f"------------------")
            key = computedkeys[idx]
            encrypted_code = msg_list[msgidx][idx]
            cg = do_decrypt(encrypted_code, key)
            word = word_dict.get(cg)
            #print(f"key: {key}, word: {word}")
            message = f"{message} {word}"
        printit(message)

    printit(f"--------------")
    printit(f"We only have the first 8 words of the last message")
    printit(f"computing the following prime number we can complete")
    printit(f"rest of the final message.")
    currnum = computedkeys[-1]
    lastmsgidx = len(msg_list)-1
    lastmsglen = len(msg_list[lastmsgidx])
    idx = lastmsglen - len(computedkeys) + 2
    while idx < lastmsglen:
        currnum = next_prime(currnum)
        encrypted_code = msg_list[lastmsgidx][idx]
        cg = do_decrypt(encrypted_code, currnum)
        word = word_dict.get(cg)
        message = f"{message} {word}"
        idx += 1
    message = message.lstrip()
    printit(f"Final Message: <{message}>")

    return message


if __name__ == "__main__":
    # # Pnwtools debugging
    # # context.log_level = 'debug'

    parser = argparse.ArgumentParser()
    parser.add_argument("--msgs", default='/data/encrypted_msgs.txt')
    parser.add_argument("--dict", default='/data/word_dictionary.json')
    parser.add_argument("--v", default=False)
    args = parser.parse_args()
    VERBOSE = args.v

###
    if VERBOSE == False:
        # get host from environment
        host = os.getenv("CHAL_HOST", "172.17.0.1")
        if not host:
            print("No HOST supplied from environment")
            sys.exit(-1)

        # get port from environment
        port = int(os.getenv("CHAL_PORT","12345"))
        if port == 0:
            print("No PORT supplied from environment")
            sys.exit(-1)

        # get ticket from environment
        ticket = os.getenv("TICKET")

        # connect to service
        print(f"Connect to {host}:{port}", flush=True)
        r = remote(host,port)
    
        # pass ticket to ticket-taker
        if ticket:
            prompt = r.recvuntil("Ticket please:")  # "Ticket please:"
            r.sendline((ticket).encode('UTF-8'))

        # receive challenge
        challenge = r.recvuntil(b"plain text of the last message: \n").decode('UTF-8')
        print(challenge, end='', flush=True)
    
###

    #print(args)
    solution = main(args)

    if VERBOSE == False:
        # send solution
        r.sendline(solution.encode('UTF-8'))

        print(solution, flush=True)
        flag_resp = r.recvuntil(b"--END")
        print(f"{flag_resp.decode('UTF-8')}", flush=True)

