FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gnuradio

RUN volk_profile

WORKDIR /solver
ADD solver.py solver.sh /solver/

CMD ["/bin/bash", "-c", "./solver.sh"]