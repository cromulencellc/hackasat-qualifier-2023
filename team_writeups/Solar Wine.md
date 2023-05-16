3 - Dashing
A spectral analysis of a provided WAV file shows a morse signal (at around 180Hz) is drowned in white noise. By applying a bandpass filter to isolate this frequency, the morse code can then simply be decoded to obtain the flag.

27 - Magic Space Bussin
This challenge implemented a bus connected to 2 star trackers. Vulnerabilities in its implementation allowed to leak arbitrary data from the heap, and to trigger a controlled double free. Using these primitives, it is possible to find the address of the libc, write an arbitrary hook calling the "system" function, and open a shell to obtain the flag.