FROM python:3

RUN apt-get update
RUN pip install wavio numpy

WORKDIR /generator
COPY --from=has4/quals/generator-base/generator-base:latest /upload/ /upload
ADD morsegen.py /generator/
ADD make_challenge.sh /generator/

CMD ["/bin/bash", "-c", "./make_challenge.sh"]
