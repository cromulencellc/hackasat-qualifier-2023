FROM has4/quals/challenges/challenge/bskchallenge:latest

RUN apt update && apt install tini

WORKDIR /challenge
COPY *.py /challenge/

CMD ["tini", "--", "python3", "challenge.py"]
