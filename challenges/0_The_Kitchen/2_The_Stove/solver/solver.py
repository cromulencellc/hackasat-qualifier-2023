from pwn import *

import argparse

# Hello World Solver
import os
import sys
import socket

context.log_level = 'debug'

if __name__ == "__main__":
    # get host from environment
    hostname = os.getenv("CHAL_HOST")
    if not hostname:
        print("No HOST supplied from environment")
        sys.exit(-1)

    # get port from environment
    port = int(os.getenv("CHAL_PORT","0"))
    if port == 0:
        print("No PORT supplied from environment")
        sys.exit(-1)

    
    # get ticket from environment
    ticket = os.getenv("TICKET")

    r = remote( hostname , port )
    
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline(bytes(ticket, 'utf-8'))    

    # Get the keys 
    r.recvuntil(b"flag:")
    r.sendline(b"flag please")
    r.recvall()