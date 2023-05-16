# warning

**Category:** Pure Pwnage
**Relative Difficulty:** 1/5
**Author:** MeenMachine @ [Cromulence](https://cromulence.com/)

I use whatever compiler gives me the least warnings 🤷‍♂️. Wait, you're saying everyone just ignores warnings anyways?

Dope. Let's fly

## Notes

* The first bug is an uninitialized bug in C++ that @cydonia discovered in some code.
  - Member initializer lists are actually initialized in the order they are declared
  in the class defintion, not the order they are declared in the member initialzer
  list. clang++ actually prints out a warning about it, g++ does not.

* The second bug is a straight forward overflow

* The third bug is modeled after the [T-BONE Tesla exploit](https://kunnamon.io/tbone/tbone-v1.0-redacted.pdf)
  - Incrementation of a pointer allows for OOB write and lets you hop over a stack canary.
  - The code in the challenge is contrived, but is modeled after the Connman code that 
    was vulnerable.