The challenge spectral imaging was a timing based attack using speculative execution. The image struct contained a map of star data and a list of stars in a sequence. Conveniently, the flag was placed in the struct immediately after the sequence data. The idea was to use branch misprediction to allow a speculative out-of-bounds read on the sequence array, instead using value of the flag. If data for star N was speculatively accessed, subsequent reads will be faster as the data was placed in cache.