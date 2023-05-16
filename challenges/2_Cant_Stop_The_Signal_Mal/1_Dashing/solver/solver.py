import os
import wavio
import numpy as np
from morse_audio_decoder.morse import MorseCode

def main():
    sound = wavio.read("../mnt/beepboop.wav")
    signal = sound.data

    # get some data about the signal
    SIGNAL_LEN = len(signal)
    SAMPLE_RATE = sound.rate
    DURATION = SIGNAL_LEN / SAMPLE_RATE

    # fft the signal, axis=0 is very important otherwise it'll return the unFFTed signal
    yf = np.fft.fft(signal, axis=0)

    # frequency we want to filter around
    FREQ = 200

    # target the area of the FFT vector / frequency domain / idk representing 200 Hz
    target_idx_l = int(SIGNAL_LEN / (SAMPLE_RATE) * FREQ)
    target_idx_r = int(SIGNAL_LEN - (SIGNAL_LEN / (SAMPLE_RATE) * FREQ))
    print(f'{SIGNAL_LEN=} {SAMPLE_RATE=} {DURATION=}')
    print(f'{target_idx_l=} {target_idx_r=}')

    BANDSIZE = 5000
    # 0 out the frequencies not near 200 Hz
    yf[:target_idx_l - BANDSIZE] = 0
    yf[target_idx_l + BANDSIZE:target_idx_r - BANDSIZE] = 0
    yf[target_idx_r + BANDSIZE:] = 0

    # inverse FFT the signal to get a waveform back
    isolatedmorse = np.fft.ifft(yf, axis=0)

    # write to a file (ideally can be avoided but didn't get around to modifying the MAD library to read from variable)
    wavio.write("../mnt/filtered.wav", isolatedmorse.astype(signal.dtype), 44100, sampwidth=2)

    morse_code = MorseCode.from_wavfile("../mnt/filtered.wav")
    hexout = morse_code.decode()
    print(hexout)

    flag = bytes.fromhex(hexout).decode('utf-8')
    print(flag)
        
if __name__ == '__main__':
    main()