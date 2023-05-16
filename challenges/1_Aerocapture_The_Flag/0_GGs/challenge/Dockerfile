FROM has4/quals/challenges/challenge/bskchallenge:latest

RUN apt update && apt install tini

WORKDIR /challenge
COPY reqs.txt ./
RUN pip3 install -r reqs.txt
COPY *.py /challenge/
COPY templates templates
RUN mkdir /challenge/static

CMD ["tini", "--", "python3", "challenge.py"]