"""Command line interface"""

import argparse
from pathlib import Path
import sys

from morse_audio_decoder.morse import MorseCode


def main(argv: list[str] = None) -> None:
    """Read WAV file, process it and write outputs to stdout

    Args:
        argv (list[str]): List of command line arguments. Defaults to None.

    Raises:
        UserWarning: If dash/dot separation cannot be made unambiguosly,
            or if input file does not exist.
    """
    parsed_args = _parse_args(argv)
    file = parsed_args.WAVFILE

    if not Path(file).exists():
        sys.stderr.write(f"File {file} not found, exiting.\n")
        sys.exit(1)

    try:
        decoded = MorseCode.from_wavfile(file).decode()
        sys.stdout.write(decoded + "\n")
    except UserWarning as err:
        sys.stderr.write(f"{err}\n")
        sys.exit(1)


def _parse_args(args: list[str]) -> argparse.Namespace:
    """Parse arguments from command line"""
    parser = argparse.ArgumentParser(
        description="""Read audio file in WAV format, extract the morse code and
        write translated text into standard output."""
    )
    parser.add_argument("WAVFILE", help="Input audio file")
    return parser.parse_args(args)


if __name__ == "__main__":
    main()
