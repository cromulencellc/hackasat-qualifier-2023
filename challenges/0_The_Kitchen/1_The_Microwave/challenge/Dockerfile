FROM has4/quals/challenges/challenge/pychallenge:latest

RUN pip3 install flask
EXPOSE 7000
WORKDIR /challenge
COPY *.py /challenge/
COPY templates/ /challenge/templates/
CMD python3 challenge.py 
