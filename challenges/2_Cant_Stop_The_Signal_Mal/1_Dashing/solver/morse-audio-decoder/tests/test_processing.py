"""Test audio signal processing"""

import numpy as np
from numpy.testing import assert_array_equal, assert_array_almost_equal
import pytest

from morse_audio_decoder.processing import smoothed_power, squared_signal


@pytest.fixture(name="data")
def data_fx() -> np.ndarray:
    """Create sample data (1 second of 600 Hz sine wave)"""
    return (np.sin(np.linspace(0, 600 * np.pi * 2, 44100)) * (2**15 - 1)).astype(
        np.int16
    )


@pytest.fixture(name="squared_smoothed_step")
def squared_smoothed_step_fx() -> np.ndarray:
    """Create squared signal out of smoothed signal from a stepwise on/off signal

    - 1000 samples silence
    - 1000 samples sine wave
    - 1000 samples silence

    Window width is 200 samples.
    """
    step_data = np.concatenate(
        (
            np.zeros(1000),
            (
                np.sin(np.linspace(0, 600 * np.pi * 2 / 44100 * 1000, 1000))
                * (2**15 - 1)
            ).astype(np.int16),
            np.zeros(1000),
        )
    )
    smoothed_step_data = smoothed_power(step_data, 200, mode="same")
    return squared_signal(smoothed_step_data)


def test_smoothed_power_rms(data: np.ndarray):
    """Test that RMS value is almost equal to peak/sqrt(2)

    It will not be exactly equal, as Hann window smoothing retains some ripple
    """
    received = smoothed_power(data, 44100 // 600 * 4)
    expected = (
        np.ones(len(data) - 44100 // 600 * 4 + 1) / np.sqrt(2) * (2**15 - 1)
    ).astype(np.int16)

    assert_array_equal(received // 100, expected // 100)


def test_smoothed_power_rms_float():
    """Test that RMS of sine wave is almost 1/sqrt(2)

    It will not be exactly equal, as Hann window smoothing retains some ripple
    """
    data = np.sin(np.linspace(0, 600 * np.pi * 2, 44100))

    received = smoothed_power(data, 44100 // 600 * 4)
    expected = np.ones(len(data) - 44100 // 600 * 4 + 1) / np.sqrt(2)

    assert_array_almost_equal(received, expected, 3)


def test_smoothed_power_uint8():
    """Uint8 also works?"""
    data = np.round(
        (np.sin(np.linspace(0, 600 * np.pi * 2, 44100)) + 1) / 2 * (2**8 - 1)
    ).astype(np.uint8)

    received = smoothed_power(data, 44100 // 600 * 4)
    expected = (np.ones(len(data) - 44100 // 600 * 4 + 1) / np.sqrt(2) * 128).astype(
        np.uint8
    )

    assert_array_almost_equal(received, expected, 3)


def test_smoothed_power_dtype(data):
    """Output dtype is int16 for int16 input"""
    received = smoothed_power(data, 44100 // 600)

    assert received.dtype == data.dtype


def test_smoothed_power_same(data):
    """Window length is equal to input length"""
    received = smoothed_power(data, 44100 // 600, mode="same")

    assert received.size == data.size


def test_squared_signal_start(squared_smoothed_step):
    """Signal start is less than 25% window width apart from actual start"""

    received_start_idx = np.nonzero(squared_smoothed_step)[0][0]

    assert np.abs(1000 - received_start_idx) < 0.25 * 200


def test_squared_signal_end(squared_smoothed_step):
    """Signal end is less than 25% window width apart from actual end"""

    received_end_idx = np.nonzero(squared_smoothed_step)[0][-1]

    assert np.abs(2000 - received_end_idx) < 0.25 * 200


def test_squared_signal_between(squared_smoothed_step):
    """Between start and end, there are only 1 values"""
    start = np.nonzero(squared_smoothed_step)[0][0]
    end = np.nonzero(squared_smoothed_step)[0][0]

    assert_array_equal(squared_smoothed_step[start:end], np.ones(end - start))


def test_squared_signal_dtype(squared_smoothed_step):
    """Test that values are of int8 type"""
    assert squared_smoothed_step.dtype == np.int8


def test_squared_signal_shape(squared_smoothed_step):
    """Test that shape is same as original"""
    assert squared_smoothed_step.shape == (3000,)
