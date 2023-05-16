FROM python:3.10-slim

RUN pip3 install numpy scipy matplotlib

WORKDIR /solver/
COPY *.py /solver/
COPY solve.sh /solver/
RUN chmod +x solve.sh
VOLUME /data

CMD ./solve.sh