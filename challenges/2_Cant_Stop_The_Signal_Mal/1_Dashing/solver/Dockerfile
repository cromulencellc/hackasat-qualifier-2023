FROM python:3.10

RUN apt-get update
RUN pip install wavio numpy

ADD morse-audio-decoder/ /mad/
# RUN pip install morse-audio-decoder
RUN pip install /mad/

WORKDIR /solver
ADD solver.py /solver/

CMD ["python3", "solver.py"]