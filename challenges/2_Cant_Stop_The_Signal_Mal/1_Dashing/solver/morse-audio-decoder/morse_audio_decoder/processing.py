"""Audio signal processing"""

import numpy as np


def smoothed_power(
    data: np.ndarray, window_size: int, mode: str = "valid"
) -> np.ndarray:
    """Calculate moving time window RMS power for a signal

    Produce amplitude envelope, which reperesents signal power over time.
    Power is calculated as RMS (root mean squared) value.
    The envelope is smoothed by Hann window convolution.

    Args:
        data (np.ndarray): Input data
        window_size (int): Smoothing window length, samples
        mode (str): Convolution mode, one of  "same" and "valid".
            When "same", return same length array as in input; when "valid",
            convolution is only given for signal points that fully overlap with
            the smoothing window. See np.convolve documentation
            for further explanation.

    Returns:
        np.ndarray: smoothed array
    """
    # Convert data in order to avoid truncation errors
    if data.dtype == np.uint8:
        secure_data = data.astype(np.int16) - 128
    elif np.issubdtype(data.dtype, np.integer):
        secure_data = data.astype(np.int32) if data.itemsize < 32 else data
    else:
        secure_data = data.astype(np.float32) if data.itemsize < 32 else data

    # Create window with integral=1 -> multiplication results in weighted average
    window = np.hanning(window_size)
    window = window / sum(window)

    squared = np.power(secure_data, 2)

    return np.sqrt(np.convolve(squared, window, mode)).astype(data.dtype)


def squared_signal(data: np.ndarray, threshold: int | float = None) -> np.ndarray:
    """Convert signal to binary 0/1 based on threshold value

    Args:
        data (np.ndarray): Input data
        threshold (int | float, optional): Threshold value. All values in data
            that are smaller than threshold value are converted to 0, larger values
            are converted to 1. Defaults 0.5 * max(data).

    Returns:
        np.ndarray: Binary array of int8 dtype, same shape as original
    """
    threshold = threshold or 0.5 * np.max(data)
    return np.where(data > threshold, 1, 0).astype(np.int8)
