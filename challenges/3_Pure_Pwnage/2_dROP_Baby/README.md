# dROP_baby

**Category:** Pure Pwnage
**Relative Difficulty:** 2/5
**Author:** [Cromulence](https://cromulence.com/)

This service builds on Smash Baby but changes a lot of stuff. The stack is no longer executable so you have to ROP and now you have to find a format string bug to leak a stack pointer. The pointer leak is only necessary if the player's configuration is different than the challenge running in infrastrcture. 

Another complication is that some of the buffer read lengths are not in the binary but are loaded at runtime from a file they are not given. Built in features will show these settings after the commands are reverse engineered.


# Running the challenge

I run this challenge under the QEMU user mode riscv32 emulator. It uses STDIN/STDOUT for all interactive I/O.

    qemu-riscv32 drop-baby

# Compiling

riscv32-unknown-linux-gnu-gcc -static *.c -o drop-baby 

Or use the include Makefile provided.


# Information the teams will need

The drop-baby binary, but NOT the server.ini file. I'd also tell them that it is running under user mode emulation using qemu-riscv32 on Ubuntu 22.04. 