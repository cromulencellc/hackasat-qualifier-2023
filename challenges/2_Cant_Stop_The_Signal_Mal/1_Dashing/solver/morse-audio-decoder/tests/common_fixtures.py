"""Fixtures that are common with multiple test classes"""

from pathlib import Path

import pytest


@pytest.fixture(name="wav_file")
def wav_file_fx() -> Path:
    """Provide path to beep.wav"""
    return Path(__file__).parent / "fixtures" / "beep.wav"


@pytest.fixture(name="wav_file_8bit")
def wav_file_8bit_fx():
    """Provide path to cq.wav"""
    return Path(__file__).parent / "fixtures" / "cq.wav"
