"""Test morse code handling"""

from pathlib import Path

import numpy as np
from numpy.testing import assert_array_equal
import pytest

from morse_audio_decoder.morse import MorseCode

# pylint: disable=unused-import
from .common_fixtures import (
    wav_file_fx,
    wav_file_8bit_fx,
)


@pytest.fixture(name="hello_world_morse")
def hello_world_morse_fx() -> str:
    """HELLO WORLD string in morse"""
    return ".... . .-.. .-.. ---|.-- --- .-. .-.. -.."


@pytest.fixture(name="hello_data")
def hello_data_fx(hello_world_morse: str) -> np.ndarray:
    """Add dummy data for HELLO WORLD string"""
    return _dash_dot_to_square_data(hello_world_morse)


def _dash_dot_to_square_data(dash_dot_str: str, padding=True) -> np.ndarray:
    binary_str = (
        dash_dot_str.replace(" ", "00")
        .replace("|", "000000")
        .replace(".", "10")
        .replace("-", "1110")
    )
    if padding:
        binary_str = "000" + binary_str + "00"
    else:
        binary_str = binary_str[:-1]
    return np.repeat(np.array([int(i) for i in binary_str]), 44100 * 60 // 1000)


@pytest.fixture(name="off_samples")
def off_samples_fx(hello_world_morse: str):
    """Serve off samples for tests"""
    pairs = [
        hello_world_morse.replace("-", ".")[i : i + 2]
        for i in range(len(hello_world_morse) - 1)
    ]
    pair_off_lens = {"..": 1, ". ": 3, ".|": 7}
    expected_off = (
        np.array(
            list(map(pair_off_lens.get, [p for p in pairs if p not in [" .", "|."]]))
        )
        * 44100
        * 60
        // 1000
    )
    return expected_off


def test_from_wavfile(wav_file: Path):
    """Constructor runs and data is initalized with something"""
    received = MorseCode.from_wavfile(wav_file)

    assert len(received.data) > 0


def test_from_wavfile_8bit(wav_file_8bit: Path):
    """Construction with 8bit input data also works"""
    received = MorseCode.from_wavfile(wav_file_8bit)

    assert len(received.data) > 0


test_cases = [
    ("HELLO WORLD", ".... . .-.. .-.. ---|.-- --- .-. .-.. -.."),
    ("CQ", "-.-. --.-"),
    ("E", "."),
    ("M", "--"),
    ("I", ".."),
]


@pytest.mark.parametrize("expected, code", test_cases)
def test_decode(expected, code):
    """Dummy data decoding works"""
    data = _dash_dot_to_square_data(code)
    received = MorseCode(data, 44100).decode()

    assert received == expected


@pytest.mark.parametrize("expected, code", [("E", "."), ("T", "-")])
def test_decode_char_length_guessed(expected, code, capsys):
    """Guessing based on 20 wpm can distinguish single-character letters"""
    data = _dash_dot_to_square_data(code)

    received = MorseCode(data, 44100).decode()
    captured = capsys.readouterr()

    assert received == expected
    assert captured.err == "WARNING: too little data, guessing based on 20 wpm"


def test_decode_unable_to_guess_exit():
    """Raise error if unable to guess dash/dot"""
    data = _dash_dot_to_square_data(".")

    with pytest.raises(UserWarning):
        MorseCode(data).decode()


def test_decode_empty_input():
    """Empty input results in empty output"""
    received = MorseCode(np.array([], dtype="int"), 44100).decode()
    assert received == ""


def test_morse_to_char():
    """All alphanumeric characters and full stop are in values"""
    received = MorseCode(np.empty(1)).morse_to_char
    expected_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ."

    assert set(received.values()).issuperset(expected_chars)


def test_morse_to_char_cached(mocker):
    """Cached dictionary is read from MorseCode._morse_to_char"""
    expected = {"..": "A"}
    mocker.patch("morse_audio_decoder.morse.MorseCode._morse_to_char", expected)
    morse = MorseCode(np.empty(1))

    received = morse.morse_to_char

    assert received == expected


def test_on_off_samples(
    hello_data: np.ndarray, hello_world_morse: str, off_samples: np.ndarray
):
    """Count of samples is detected correctly"""
    on_str = (
        hello_world_morse.replace(" ", "")
        .replace("|", "")
        .replace(".", "1")
        .replace("-", "3")
    )
    expected_on = np.array([int(i) for i in on_str]) * 44100 * 60 // 1000

    # pylint: disable=protected-access
    received_on, received_off = MorseCode(hello_data)._on_off_samples()

    assert_array_equal(received_on, expected_on)
    assert_array_equal(received_off, off_samples)


def test_on_off_samples_no_padding(hello_data: np.ndarray, hello_world_morse: str):
    """Test that output is equal, whether or not there is empty space at start/end"""
    hello_data_no_pad = _dash_dot_to_square_data(hello_world_morse, False)

    # pylint: disable=protected-access
    expected_on, expected_off = MorseCode(hello_data)._on_off_samples()
    received_on, received_off = MorseCode(hello_data_no_pad)._on_off_samples()

    assert_array_equal(received_on, expected_on)
    assert_array_equal(received_off, expected_off)


def test_dash_dot_characters(hello_world_morse: str):
    """Sample length to dash/dot conversion"""
    dash_dots = hello_world_morse.replace(" ", "").replace("|", "")

    on_str = dash_dots.replace(".", "1").replace("-", "3")
    on_samples = np.array([int(i) for i in on_str]) * 44100 * 60 // 1000

    # pylint: disable=protected-access
    received = MorseCode(np.empty(1))._dash_dot_characters(on_samples)
    expected = np.array(list(dash_dots))

    assert_array_equal(received, expected)


def test_break_spaces(hello_world_morse: str, off_samples: np.ndarray):
    """Space and word breaks are found correctly"""
    all_same_spaces = hello_world_morse.replace("|", " ")
    char_break_idx = np.nonzero(np.array(list(all_same_spaces)) == " ")[0]
    char_break_idx = char_break_idx - np.arange(len(char_break_idx))

    word_space_idx = np.nonzero(np.array(list("HELLO WORLD")) == " ")[0]

    # pylint: disable=protected-access
    received_cb, received_wb = MorseCode(np.empty(1))._break_spaces(off_samples)

    assert_array_equal(received_cb, char_break_idx)
    assert_array_equal(received_wb, word_space_idx)


def test_morse_words(hello_world_morse: str):
    """Expansion of character and space arrays works as expected"""
    only_dash_dots = hello_world_morse.replace("|", "").replace(" ", "")
    dash_dot_characters = np.array(list(only_dash_dots))

    all_same_spaces = hello_world_morse.replace("|", " ")
    char_break_idx = np.nonzero(np.array(list(all_same_spaces)) == " ")[0]
    char_break_idx = char_break_idx - np.arange(len(char_break_idx))

    word_space_idx = np.nonzero(np.array(list("HELLO WORLD")) == " ")[0]

    # pylint: disable=protected-access
    received = MorseCode(np.zeros(10))._morse_words(
        dash_dot_characters, char_break_idx, word_space_idx
    )
    expected = [word.split(" ") for word in hello_world_morse.split("|")]

    assert received == expected


def test_translate(hello_world_morse: str):
    """Correct translation is received"""
    morse_words = [word.split(" ") for word in hello_world_morse.split("|")]

    # pylint: disable=protected-access
    received = MorseCode(np.zeros(10))._translate(morse_words)
    expected = "HELLO WORLD"

    assert received == expected
