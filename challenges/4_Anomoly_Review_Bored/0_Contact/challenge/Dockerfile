FROM has4/quals/challenges/challenge/pychallenge:latest

USER challenge

RUN pip3 install skyfield

WORKDIR /challenge
COPY *.py /challenge
CMD ["tini", "--", "python3", "challenge.py"]