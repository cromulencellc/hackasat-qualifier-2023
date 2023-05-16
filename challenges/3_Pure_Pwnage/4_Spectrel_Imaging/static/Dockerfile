FROM ubuntu:jammy as builder
ARG DEBIAN_FRONTEND=noninteractive

ARG TZ=Etc/UTC

RUN apt update && \ 
    apt install -y build-essential cmake

WORKDIR /builder
COPY *.cpp /builder/  
COPY *.hpp /builder/ 
COPY *.txt /builder/
RUN cmake -B /builder/build . && \
    cmake --build /builder/build/
# put the imager somewhere handy

WORKDIR /binary/
RUN cp  /builder/build/ImagerScheduler .
# Make a compressed archive for the players - binary - example files

WORKDIR /out/
RUN cp  /builder/build/ImagerScheduler .
COPY readme.md ./ 
COPY flag.txt ./
COPY exampleCmds.txt ./
COPY challenge.sh ./ 
COPY stars.csv ./
RUN bzip2 -zkf exampleCmds.txt  && \ 
    rm exampleCmds.txt && \ 
    mv exampleCmds.txt.bz2 submission.bz2
RUN tar -zcvf ../imager.tar.gz .

VOLUME /data/

ENTRYPOINT cp ../imager.tar.gz /data/