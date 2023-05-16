FROM has4/quals/challenges/ctfphasedarray:latest


WORKDIR /generator
COPY --from=has4/quals/generator-base/generator-base:latest /upload/ /upload
USER root
RUN pip3 install numpy scipy
COPY *.py /generator/
COPY gen.sh /generator/
RUN chmod +x gen.sh
VOLUME /out
CMD ./gen.sh
