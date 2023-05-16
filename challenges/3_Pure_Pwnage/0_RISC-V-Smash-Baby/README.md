# risc-v-smash-baby

**Category:** Pure Pwnage
**Relative Difficulty:** 1/5
**Author:** [Cromulence](https://cromulence.com/)

A baby's first type challenge for the RISC-V architecture. This one is simple with an executable stack and a simple buffer overflow. At startup the challenge gets the flag from the environment and writes it to a file flag.txt, then clears the env variable. To exploit it, contestants will need to craft shellcode to read in the file and write it to stdout. Since this is a baby's first type challenge, it prints an address on the stack in main() to help them deal with differences in runtime environments. 


# Running the challenge

I run this challenge under the QEMU user mode riscv32 emulator. It uses STDIN/STDOUT for all interactive I/O.

    qemu-riscv32 smash-baby

# Compiling

riscv32-unknown-linux-gnu-gcc -static -z execstack  main.c -o smash-baby 

Or use the include Makefile provided.


