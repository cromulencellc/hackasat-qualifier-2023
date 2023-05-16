FROM has4/quals/challenges/challenge/pychallenge:latest
USER root
WORKDIR /challenge
COPY keygen.py /challenge
COPY requirements.txt /challenge
COPY 56640-keys /challenge
RUN pip3 install -r /challenge/requirements.txt
#RUN python3 keygen.py # this takes waaaay too long so we're going to store the binary and gitlfs commit it
# Do this after we generate the keys so things dont take forever
COPY quantum.py /challenge

USER challenge
#CMD python3 /challenge/quantum.py --key-file /challenge/56640-keys
CMD ["tini", "--", "python3", "quantum.py","--key-file","/challenge/56640-keys"]