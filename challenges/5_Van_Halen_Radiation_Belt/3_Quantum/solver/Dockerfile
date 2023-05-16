FROM has4/quals/challenges/challenge/pychallenge:latest
USER root
WORKDIR /challenge
COPY solver.py /challenge
COPY requirements.txt /challenge
RUN pip3 install -r /challenge/requirements.txt
USER challenge
CMD python3 /challenge/solver.py