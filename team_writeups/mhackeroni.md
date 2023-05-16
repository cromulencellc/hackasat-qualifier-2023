QAM - Once the encoding is known, the solution is just a matter of decoding each symbol to get the 4 bits it represents, concatenating all the bits and printing out the flag.
FAUXY Lady - Our approach started with the analisys of the signal inside GNURadio Companion, we set the sample rate to 44.1Khz, imported the file with a Wav file source block and converted it into complex type using a Float to Complex block. We then used a BPSK Demodulator block guessing the baudrate while also watching the output with a Time Sink block. As soon as we set baudrate to 1200 and Differential to True we got a nice square wave out. We then exported the bitstream and further processed it Python.

Data processing
The challenge description mentioned differential encoding, so the first step we applied was a differential decoder:

for b in bits:
out.append(b ^ prev)
prev = b
Printing out the resulting bits, we noticed that after the first section where there was some noise, splitting the text in 8 bit chunks only ever produced two bitstrings:

00000000
10000001
We guessed that each of these represented a single bit in the message, and we also knew from the challenge description that the packets we were looking for started with a magic number of 0x1ACFFC1D. We looked for a bit mapping that contained the magic, and decoded the bitstream, mapping 00000000 to 1 and 10000001 to 0.

Finally, we extracted the three packets contained in the bitstream and printed their contents, revealing the three parts of the flag.