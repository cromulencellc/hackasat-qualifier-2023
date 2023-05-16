FROM ubuntu:focal as builder

ARG DEBIAN_FRONTEND=noninteractive

ARG TZ=Etc/UTC
RUN apt-get -y update \
    && apt-get upgrade -y \
    && apt-get install -y \
    build-essential \
    # gcc \
    # python \
    python3.8 \
    python3-setuptools \
    python3-tk \
    python3-pip \
    python3-venv \
    python3-dev \
    swig \
    git \
    neovim \
    wget \
    curl \
    && apt-get clean \
    && apt-get autoclean \ 
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv
ENV PATH="/venv/bin:${PATH}"
RUN pip3 install --upgrade pip --no-cache && \
    pip3 install wheel --no-cache && \
    pip3 install conan==1.59.0 &&\ 
    pip3 install cmake numpy astropy matplotlib pytest pandas Pillow parse --no-cache

ARG BSK_TAG=2.1.3

RUN git clone --depth=1 --branch=${BSK_TAG} https://bitbucket.org/avslab/basilisk.git /bsk/ 

ARG BUILD_TYPE=Debug

WORKDIR /bsk
RUN pip3 list  && \
    python3 conanfile.py --buildType ${BUILD_TYPE} && \
    python3 conanfile.py --buildType ${BUILD_TYPE} && \
    cd dist3 && \
    if [ "${BUILD_TYPE}" = "Release" ]; then \
        find Basilisk -name "*.so" -type f | xargs strip -S && \
        rm -rf CMakeFiles; \
    fi


#FROM python:3.10-slim
#COPY --from=builder /venv /venv

ENV PATH="/venv/bin:${PATH}"

WORKDIR /ctf/
COPY --from=has4/quals/challenges/ctfpythonbase /ctf/dist/*.whl .

WORKDIR /bsk

RUN useradd -ms /bin/bash challenge
#USER challenge