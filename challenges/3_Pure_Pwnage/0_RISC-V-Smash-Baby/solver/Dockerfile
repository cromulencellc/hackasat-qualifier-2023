FROM python:3.10-slim

RUN pip3 install pwntools

WORKDIR /solver
COPY *.py /solver/
CMD python3 pov.py