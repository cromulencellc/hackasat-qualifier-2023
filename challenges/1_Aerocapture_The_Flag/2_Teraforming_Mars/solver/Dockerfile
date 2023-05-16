FROM python:3.10-slim
WORKDIR /solver
RUN pip3 install pwntools numpy
COPY *.py /solver/
COPY *.txt /solver/
CMD python3 solver.py --host $CHAL_HOST --port $CHAL_PORT --maneuvers solution.txt

