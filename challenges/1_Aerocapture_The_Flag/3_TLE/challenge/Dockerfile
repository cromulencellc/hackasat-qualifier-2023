FROM has4/quals/challenges/challenge/pychallenge:latest
USER root
RUN apt update && apt install tini


WORKDIR /challenge
COPY reqs.txt /challenge/
RUN pip3 install -r reqs.txt 
USER challenge

COPY *.py /challenge
COPY *.tle /challenge/
CMD ["tini", "--", "python3", "challenge.py"]