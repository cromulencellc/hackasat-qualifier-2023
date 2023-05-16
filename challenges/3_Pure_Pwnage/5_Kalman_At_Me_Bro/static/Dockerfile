FROM has4/quals/challenges/kalman-at-me-bro:base
ARG DEBIAN_FRONTEND=noninteractive

ARG TZ=Etc/UTC


WORKDIR /downloads/
RUN wget https://gitlab.com/libeigen/eigen/-/archive/3.4.0/eigen-3.4.0.zip && \
    unzip eigen-3.4.0.zip && \
    mkdir -p /usr/include/eigen3 && \
    cp -r eigen-3.4.0/Eigen /usr/include/eigen3/

RUN pip3 install numpy scipy

WORKDIR /home/builder 
VOLUME /binaries 
COPY *.hpp ./
COPY *.cpp ./
COPY CMakeLists.txt ./
COPY *.sh ./
COPY Dockerfile_Public ./Dockerfile
COPY *.py ./

RUN mkdir /kalman

RUN python3 data.py &&\
    cp positions.bin /kalman/ &&\
    cp accels.bin /kalman/

RUN cmake -B build . &&\
    cmake --build build &&\
    cp ./Dockerfile /kalman/ &&\
    cp ./build/Kalman /kalman/
RUN cd /kalman  &&\
    tar cvzf kalman.tar.gz /kalman/*


ENTRYPOINT [ "cp","/kalman/kalman.tar.gz","/binaries" ]
