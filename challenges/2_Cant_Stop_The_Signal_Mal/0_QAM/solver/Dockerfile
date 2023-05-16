FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gnuradio

RUN volk_profile

WORKDIR /solver
ADD solver.py solver_epy_block_0.py solver.sh /solver/
VOLUME /out

CMD ./solver.sh