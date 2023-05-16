FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt upgrade -y && \
    apt update -y && \
    apt install -y wget \
                   tar \
                   python3 \
                   python3-pip \
                   npm

WORKDIR /challenge

# Get and unpack gmat

RUN wget https://sourceforge.net/projects/gmat/files/GMAT/GMAT-R2020a/gmat-ubuntu-x64-R2020a.tar.gz/download && \
    tar xvf download
# Update NODE
RUN npm cache clean -f &&\
    npm install -g n &&\
    n stable 

RUN pip3 install scipy numpy

WORKDIR /ctf/
COPY --from=has4/quals/challenges/ctfpythonbase /ctf/dist/*.whl .

WORKDIR /challenge
