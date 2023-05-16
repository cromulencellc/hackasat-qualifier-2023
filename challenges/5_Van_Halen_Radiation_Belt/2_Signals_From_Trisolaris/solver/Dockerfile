FROM python:3.10-slim
WORKDIR /solver
COPY reqs.txt ./

RUN pip3 install -r reqs.txt
COPY *.py /solver/
COPY run.sh /solver/
RUN chmod +x run.sh
VOLUME /data
CMD ./run.sh