FROM python:3.10-slim

WORKDIR /solver/
COPY *.py /solver/
RUN pip3 install pwntools numpy skyfield scipy matplotlib
CMD python3 solver.py --hostname ${CHAL_HOST} --port ${CHAL_PORT}