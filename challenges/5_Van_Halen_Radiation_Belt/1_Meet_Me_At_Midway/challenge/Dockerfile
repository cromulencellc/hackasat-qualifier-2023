FROM has4/quals/challenges/challenge/pychallenge:latest
USER challenge
WORKDIR /challenge

COPY ./challenge.py /challenge/

CMD ["tini", "--", "python3", "challenge.py"]