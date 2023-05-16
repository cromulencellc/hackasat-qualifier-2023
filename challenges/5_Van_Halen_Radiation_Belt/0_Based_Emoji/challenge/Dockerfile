FROM has4/quals/challenges/challenge/pychallenge:latest

WORKDIR /challenge
COPY reqs.txt ./
RUN pip3 install -r reqs.txt
USER challenge
COPY *.py /challenge/

CMD ["tini", "--", "python3", "main.py"]
