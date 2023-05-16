FROM has4/quals/challenges/ctfphasedarray:latest



WORKDIR /generator
USER root
RUN mkdir /generator/bin
COPY *.txt /generator/
RUN pip3 install -r reqs.txt 
COPY *.py /generator/

RUN python3 generate.py
WORKDIR /generator
VOLUME /data
RUN chown -R challenge:challenge /generator
RUN cp /generator/de421.bsp bin
RUN cp /generator/hip_main.dat bin
RUN cd /generator/ && \
    tar cvzf Arecibo.tar.gz bin
    
CMD [ "cp","/generator/Arecibo.tar.gz", "/data/"]