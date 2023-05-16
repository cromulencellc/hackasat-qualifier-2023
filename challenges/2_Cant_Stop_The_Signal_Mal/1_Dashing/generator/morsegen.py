import os
import wavio
import numpy as np

def text_to_morse(text):

    char_to_dots = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', ' ': ' ', '0': '-----',
        '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
        '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '&': '.-...', "'": '.----.', '@': '.--.-.', ')': '-.--.-', '(': '-.--.',
        ':': '---...', ',': '--..--', '=': '-...-', '!': '-.-.--', '.': '.-.-.-',
        '-': '-....-', '+': '.-.-.', '"': '.-..-.', '?': '..--..', '/': '-..-.',
        '_': '..--.-'
    }
    morse=[char_to_dots.get(letter.upper()) for letter in text]
    return ' '.join(morse)

def gen_sine_wave(char):

    t = .05 if char == '.' else .15 #increased from .15

    f = 200 if char != ' ' else 0

    rate = 44100
    T = 1/rate
    N = rate * t
    t_seq = np.arange(N) * T
    omega = 2*np.pi*f

    wave = np.concatenate((.01*np.sin(omega*t_seq), np.zeros(4000)))

    return wave

def code_to_sound(code):

    wave_group=np.zeros(0)
    for char in code:
        new_wave=gen_sine_wave(char)
        wave_group=np.concatenate((wave_group, new_wave))

    return wave_group

def fftnoise(f):
    f = np.array(f, dtype='complex')
    Np = (len(f) - 1) // 2
    phases = np.random.rand(Np) * 2 * np.pi
    phases = np.cos(phases) + 1j * np.sin(phases)
    f[1:Np+1] *= phases
    f[-1:-1-Np:-1] = np.conj(f[1:Np+1])
    return np.fft.ifft(f).real

def band_limited_noise(min_freq, max_freq, samples=1024, samplerate=1):
    freqs = np.abs(np.fft.fftfreq(samples, 1/samplerate))
    f = np.zeros(samples)
    idx = np.where(np.logical_and(freqs>=min_freq, freqs<=max_freq))[0]
    f[idx] = 1
    return fftnoise(f)

def main():
    flag = os.getenv("FLAG") if os.getenv("FLAG") else "FLAGERROR"

    hexflag = flag.encode('utf-8').hex()
    print(hexflag)

    #add spaces to make decoding the morse easier
    hexflag = ' '.join(hexflag[i:i+2] for i in range(0, len(hexflag), 2))
    morse_flag = text_to_morse(hexflag)
    print(morse_flag)

    morse_sound = .5 * code_to_sound(morse_flag)

    noise_under = band_limited_noise(0, 185, morse_sound.size, 44100)
    noise_over = band_limited_noise(215, 10000, morse_sound.size, 44100)

    noise = 50 * np.add(noise_under, noise_over)
    
    noisy_sound = np.add(morse_sound, noise)
    wavio.write("../mnt/beepboop.wav", noisy_sound, 44100, sampwidth=2)
    # wavio.write("../mnt/noise.wav", noise, 44100, sampwidth=2)
    
if __name__ == '__main__':
    main()