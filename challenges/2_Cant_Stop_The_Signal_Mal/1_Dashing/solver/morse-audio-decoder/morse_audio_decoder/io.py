"""Input/output"""

import os
import wave

import numpy as np


def read_wave(file: os.PathLike) -> tuple[int, np.ndarray]:
    """Read WAV file into numpy array

    NOTE: only mono audio is supported. Multi-channel audio is interlaced,
    and would need to be de-interlaced into a 2D array.

    Args:
        file (os.PathLike): input WAV file

    Returns:
        tuple[int, np.ndarray]: sample rate, data

        Data type is determined from the file; for 16bit PCM (as in competition),
        the output data type is int16. For mono audio, return shape is 1D array.
    """
    with wave.open(str(file), "rb") as wav_file:
        buffer = wav_file.readframes(wav_file.getnframes())
        sample_width_bits = wav_file.getsampwidth() * 8
        _dtype = "uint8" if sample_width_bits == 8 else f"int{sample_width_bits}"
        data = np.frombuffer(buffer, dtype=_dtype)
        if wav_file.getnchannels() > 1:
            raise NotImplementedError(
                "Cannot read WAV file with more than one channels, found: "
                + str(wav_file.getnchannels())
            )
        return wav_file.getframerate(), data
