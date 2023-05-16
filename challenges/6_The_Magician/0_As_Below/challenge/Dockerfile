FROM debian:bullseye

RUN apt-get update && \
  apt-get install -y ruby python3-pip zsh make curl && \
  curl https://raw.githubusercontent.com/wasienv/wasienv/master/install.sh | sh
  
ENV WASIENV_DIR="/root/.wasienv"

ENV WASMER_DIR="/root/.wasmer"
ENV WASMER_CACHE_DIR="$WASMER_DIR/cache"

ENV PATH="$WASMER_DIR/bin:$WASIENV_DIR/bin:$PATH:$WASMER_DIR/globals/wapm_packages/.bin"

RUN mkdir -p /challenge/src /challenge/build

WORKDIR /challenge

ADD Makefile generate.rb /challenge/
ADD src /challenge/src
