FROM has4/quals/challenges/challenge/pychallenge:latest

USER challenge
WORKDIR /challenge
COPY *.py /challenge

CMD ["tini", "--", "python3", "challenge.py"]
