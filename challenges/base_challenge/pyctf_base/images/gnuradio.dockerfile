FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gnuradio

RUN volk_profile

RUN apt-get install -y python3-pip

WORKDIR /ctf/
COPY --from=has4/quals/challenges/ctfpythonbase /ctf/dist/*.whl .

RUN useradd -ms /bin/bash chal
USER chal
