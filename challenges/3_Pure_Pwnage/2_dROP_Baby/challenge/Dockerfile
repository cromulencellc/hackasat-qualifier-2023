FROM ubuntu:22.04 as builder
RUN DEBIAN_FRONTEND=noninteractive \
  apt -y update && apt -y upgrade && \
  apt -y install wget autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev ninja-build

RUN wget https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2023.03.14/riscv32-glibc-ubuntu-22.04-nightly-2023.03.14-nightly.tar.gz
RUN tar xf riscv32-glibc-ubuntu-22.04-nightly-2023.03.14-nightly.tar.gz
ENV PATH="$PATH:/riscv/bin"
RUN mkdir -p /src
COPY src/* /src/
#WORKDIR /src
COPY Makefile .
RUN make
#RUN /riscv/bin/riscv32-unknown-linux-gnu-gcc -w -static -z execstack main.c -o drop-baby

FROM ubuntu:22.04

RUN DEBIAN_FRONTEND=noninteractive \
  apt -y update && apt -y upgrade && \
  apt -y install qemu-user 

WORKDIR /server
COPY --from=builder /build/drop-baby .
COPY server.ini /server/

CMD ["/usr/bin/qemu-riscv32","drop-baby"]
