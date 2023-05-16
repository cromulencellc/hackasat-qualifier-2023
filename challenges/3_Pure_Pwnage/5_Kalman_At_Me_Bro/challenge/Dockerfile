# Binary Container Copy
FROM has4/quals/challenges/kalman-at-me-bro:static as binary

WORKDIR /bins
RUN ls -la /home/builder/build/
RUN cp /home/builder/build/Kalman /bins/
RUN cp /home/builder/accels.bin /bins/
RUN cp /home/builder/positions.bin /bins/
RUN cp /home/builder/shared.py /bins/ 
# Actual Challenge Container
FROM has4/quals/challenges/kalman-at-me-bro:base

RUN apt update &&\
    apt install -y tini

COPY --from=has4/quals/challenges/ctfpythonbase /ctf/dist/*.whl .
RUN python3 -m pip install pyctf*.whl

WORKDIR /challenge

COPY reqs.txt reqs.txt
RUN pip3 install -r reqs.txt

COPY --from=binary  /bins/Kalman ./
COPY --from=binary /bins/*.bin ./
COPY --from=binary /bins/shared.py ./
COPY *.py /challenge/

RUN useradd -ms /bin/bash challenge
RUN chown -R challenge:challenge /challenge

USER challenge

CMD ["tini", "--", "python3", "challenge.py"]