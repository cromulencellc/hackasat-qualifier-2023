FROM python:3.10-slim
WORKDIR /solver
RUN pip3 install pwntools numpy
COPY *.py /solver/
CMD python3 solve.py --hostname $CHAL_HOST --port $CHAL_PORT
