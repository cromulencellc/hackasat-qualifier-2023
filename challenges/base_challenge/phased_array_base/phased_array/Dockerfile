FROM ubuntu:focal

RUN apt-get update  -y \
     && apt-get upgrade -y \
     && apt-get install -y --no-install-recommends\
                python3-venv \
                python-dev \
                build-essential \
                python3-pip \
                python3-setuptools \
                curl \
     && apt-get clean \
     && apt-get autoclean \ 
     && rm -rf /var/lib/apt/lists/*

RUN pip3 install build twine

WORKDIR /package/
COPY . /package/

RUN python3 -m build

VOLUME /out/

CMD ["bash", "entry.sh"]
