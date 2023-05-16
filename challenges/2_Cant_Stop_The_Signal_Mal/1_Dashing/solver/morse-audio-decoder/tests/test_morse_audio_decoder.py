"""Main tests"""

from pathlib import Path

import numpy as np
import pytest

from morse_audio_decoder import __version__
from morse_audio_decoder.__main__ import main, _parse_args


def test_version():
    """Check that version is not accidentally changed

    Make sure to update this test whenever release is made
    """
    assert __version__ == "0.1.1"


def test_main(mocker, tmp_path: Path, capsys):
    """MorseCode instance is created and decode is called"""
    file_path = tmp_path / "any_file"
    file_path.touch()

    expected = "HELLO TEST\n"

    # pylint: disable=all
    class TestClass:
        def __init__(self, data):
            self.data = data

        def decode(self):
            return "HELLO TEST"

        @classmethod
        def from_wavfile(cls, file):
            return cls(np.array([0, 1]))

    mocker.patch("morse_audio_decoder.__main__.MorseCode", TestClass)

    main([str(file_path)])
    captured = capsys.readouterr()
    assert captured.out == expected


def test_main_raises(mocker, tmp_path: Path, capsys):
    """UserWarning causes exit with error message"""
    file_path = tmp_path / "any_file"
    file_path.touch()

    err_msg = "test error message"

    # pylint: disable=all
    class TestClass:
        def __init__(self, data):
            self.data = data

        def decode(self):
            raise UserWarning(err_msg)

        @classmethod
        def from_wavfile(cls, file):
            return cls(np.array([0, 1]))

    mocker.patch("morse_audio_decoder.__main__.MorseCode", TestClass)

    with pytest.raises(SystemExit):
        main([str(file_path)])

    captured = capsys.readouterr()
    assert captured.err == err_msg + "\n"


def test_main_not_existing():
    """When file is not existing, exit"""
    with pytest.raises(SystemExit):
        main(["not-existing-filename"])


def test_parser_wavfile():
    """Argument parser receives filename"""
    test_filename = "test_file"
    parser = _parse_args([test_filename])

    assert parser.WAVFILE == test_filename
