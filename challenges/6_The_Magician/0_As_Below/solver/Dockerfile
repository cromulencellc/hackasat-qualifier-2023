FROM python:3.8-slim
RUN pip3 install six pysocks pwntools
RUN mkdir /solver

WORKDIR /solver
ADD solver.py hints.json /solver/

CMD ["python3", "solver.py"]
