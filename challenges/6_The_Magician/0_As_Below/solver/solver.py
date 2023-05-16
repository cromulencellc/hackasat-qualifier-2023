# Hello World Solver
import os
import sys
sys.path.append(os.getcwd())
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
#from pwnlib.tubes.remote import remote
from base64 import b64encode
import json

pwnlib.context.log_level = 'debug'

if __name__ == "__main__":
    # get host from environment
    host = os.getenv("CHAL_HOST", "localhost")
    if not host:
        print("No HOST supplied from environment")
        sys.exit(-1)

    # get port from environment
    port = int(os.getenv("CHAL_PORT","5000"))
    if port == 0:
        print("No PORT supplied from environment")
        sys.exit(-1)

    # get ticket from environment
    ticket = os.getenv("TICKET")

    # connect to service
    s = remote(host, port)

    # pass ticket to ticket-taker
    if ticket:
        prompt = s.recvuntil("Ticket please:")  # "Ticket please:"
        s.send((ticket + "\n").encode("utf-8"))

    hint_file = open('hints.json', 'rt')
    hints = json.load(hint_file)
    hint_file.close()
    print("Trying to solve on {}:{}".format( host , port ), flush=True)
    # receive challenge
    
    challenge_line = s.recvuntil("newline\n")
    print(challenge_line, flush=True)
    for _n in range(10):
        challenge_line = s.recvlineS()
        print("I need to solve")
        print(challenge_line, flush=True)
        [challenge, shasum] = challenge_line.split("\t")
        shasum= shasum.strip("\n")
        hint = hints[challenge]
        if not hint:
            print("didn't have hint for challenge {} with shasum {}".format(challenge, shasum) ) 
            raise ValueError
        if (hint['sha256'] != shasum):
            print("challenge {} gave shasum:\n {}\n but hint file gave:\n{}".format(challenge, shasum, hint['sha256']))
            raise ValueError

        answer = hints[challenge]['answer'].encode('utf-8')
        
        # provide response
        response = b64encode(answer)
        print("Responding with: ")
        print(response, flush=True)
        s.send(response + b"\n")

    # receive and print flag
    print(s.recvrepeatS(), flush=True)
