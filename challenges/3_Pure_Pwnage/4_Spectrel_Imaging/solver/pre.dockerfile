FROM python:3.11-slim
WORKDIR /install
COPY *.txt .
RUN pip3 install -r reqs.txt

WORKDIR /solver/

COPY *.py ./
VOLUME /data
CMD python3 genSequence.py --file /data/submission.bz2