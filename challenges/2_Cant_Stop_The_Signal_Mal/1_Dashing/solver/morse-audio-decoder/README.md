# Morse audio decoder

This program is in solution to [Wunderdog Wundernut vol. 11][wundernut], whose instructions can be found in [their GitHub][wundernut-11-github].

The program reads wav audio file, and outputs decoded morse code in standard output.

## Quickstart

### Requirements
For now, only Python 3.10 is supported.

### Installation

#### Option 1 - pip

You can install this package from pip, with

    pip install morse-audio-decoder

#### Option 2 - Local install from sources

Clone code repository from your local machine, install from there:

    git clone https://github.com/mkouhia/morse-audio-decoder.git
    cd morse-audio-decoder
    poetry build
    # take note of the build step output, install package from the dist folder
    pip install dist/PRODUCED_PACKAGE.whl

### Usage

To run the script installed with pip, perform

    morse-audio-decoder WAVFILE

or alternatively,

    python -m morse_audio_decoder WAVFILE

where `WAVFILE` is path to the audio file to be processed.

The program decodes audio morse code in the WAVFILE argument, and writes translation to standard output.
See program help with command line flag `-h`:

    $ morse-audio-decoder -h
    usage: morse-audio-decoder [-h] WAVFILE

    Read audio file in WAV format, extract the morse code and write translated text into standard output.

    positional arguments:
    WAVFILE     Input audio file

    options:
    -h, --help  show this help message and exit

### Usage in Python

```python
from morse_audio_decoder.morse import MorseCode

morse_code = MorseCode.from_wavfile("/path/to/file.wav")
out = morse_code.decode()
print(out)
```


## Technical description

The program works in following steps

1. Read in the WAV file.
2. Extract [analytic envelope][envelope-wikipedia] from the signal by calculating moving RMS amplitude with [Hann window][hann-wikipedia] of default 0.01 second width. This envelope signal is smooth and always greater than or equal to zero.
3. Convert envelope to binary 0/1 signal by applying threshold, by default `0.5 * max(envelope)`
4. Calculate durations of continuous on/off samples
5. Identify dash/dot characters and different breaks with [K-Means clustering][kmeans-wikipedia]. The lengths of periods are compared, and then labeled automatically based on number of samples.
6. Create dash/dot character array, which is then broken to pieces by character and word space indices
7. Translate morse coded characters into plain text, print output

Exploratory data analysis and first program implementation is performed in [this jupyter notebook][initial-notebook]. The notebook is not updated; actual implementation differs.


### Restrictions

This decoder has been tested and developed with inputs that have
- no noise
- constant keying speed
- constant tone pitch
- single input channel.

If the decoder were to be extended to noisy inputs with major differences, at least following changes would be required
- pitch detection in moving time
- signal extraction with narrow bandpass filter, based on identified pitch
- keying speed detection (characters/words per minute)
- decoding in smaller time steps, taking into account speed changes.

The program is also not intended to identify single characters, as the precision will be lower with shorter inputs.

## Development

### Environment

Requirements:
- Python 3.10
- Poetry (see [installation instructions][poetry-install])

Dependencies:
- Numpy
- Scikit-learn

1. Install dependencies with `poetry install`
2. Enter environment with `poetry shell`


### Code quality and testing

All code is to be formatted with `black`:

    black **/*.py

and code quality checked with `pylint`:

    pylint **/*.py

Tests should be written in `pytest`, targeting maximum practical code coverage. Tests are run with:

    pytest

and test coverage checked with

    pytest --cov

Optionally, html test coverage reports can be produced with

    pytest --cov morse_audio_decoder --cov-report html

### Contributions

Contributions are welcome. Please place an issue or a pull request.


[wundernut]: https://www.wunderdog.fi/wundernut
[wundernut-11-github]: https://github.com/wunderdogsw/wundernut-vol11
[envelope-wikipedia]: https://en.wikipedia.org/wiki/Envelope_(waves)
[hann-wikipedia]: https://en.wikipedia.org/wiki/Hann_function
[initial-notebook]: notebooks/2022-02-23%20Wundernut%2011%20exploration.ipynb
[kmeans-wikipedia]: https://en.wikipedia.org/wiki/K-means_clustering
[poetry-install]: https://python-poetry.org/docs/#installation
