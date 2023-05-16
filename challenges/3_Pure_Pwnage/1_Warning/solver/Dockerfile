FROM python:3.10-slim

RUN pip3 install pwntools

WORKDIR /solver
COPY *.py /solver

CMD python3 solver.py --hostname ${CHAL_HOST} --port ${CHAL_PORT}