FROM has4/quals/challenges/trisolaris:static as static

RUN apt update && apt install tini

FROM has4/quals/challenges/challenge/pychallenge:latest

WORKDIR /challenge
COPY --from=static /generator/starlist.py /challenge/
COPY --from=static /generator/*.bsp /challenge/
COPY --from=static /generator/*.dat /challenge/
USER challenge
COPY *.txt /challenge/
RUN pip3 install -r reqs.txt
COPY *.py /challenge

CMD ["tini", "--", "python3", "challenge.py"]

