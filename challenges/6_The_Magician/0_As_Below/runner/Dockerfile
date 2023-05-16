FROM python:3-bullseye


RUN apt-get update && \
  apt-get install -y python3-pip curl && \
  curl https://get.wasmer.io -sSfL | WASMER_DIR=/opt/wasmer sh

RUN mkdir /challenge && \
  addgroup challenge --gid 1000 && \
  adduser --disabled-password --uid 1000 --ingroup challenge --home /challenge challenge && \
  chown -R challenge:challenge /challenge

ADD as-below.tar.bz2 /challenge/

ADD runner.py timeout.py /challenge/

USER challenge:challenge

WORKDIR /challenge

ENV PATH=$PATH:/opt/wasmer/bin

CMD ["python3", "/challenge/runner.py"]
