FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gnuradio

RUN volk_profile

WORKDIR /generator
COPY --from=has4/quals/generator-base/generator-base:latest /upload/ /upload
ADD qam.py make_challenge.sh /generator/

CMD ["/bin/bash", "-c", "./make_challenge.sh | /upload/upload.sh"]