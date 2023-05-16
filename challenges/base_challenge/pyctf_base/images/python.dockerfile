FROM python:3.10-slim

RUN apt update && apt install tini

WORKDIR /ctf/

COPY --from=has4/quals/challenges/ctfpythonbase /ctf/dist/*.whl .

RUN python3 -m pip install pyctf*.whl

RUN useradd -ms /bin/bash challenge

USER challenge
