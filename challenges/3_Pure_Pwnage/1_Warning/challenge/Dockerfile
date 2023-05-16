# Binary Container Copy
FROM has4/quals/challenges/warning:static as binary

WORKDIR /bins
RUN ls -la /home/builder/build/
RUN cp /home/builder/build/warning /bins/

# Actual Challenge Container
FROM ubuntu:22.04

RUN apt update &&\
    apt install -y tini

WORKDIR /challenge

COPY --from=binary  /bins/warning ./

RUN useradd -ms /bin/bash challenge
RUN chown -R challenge:challenge /challenge

USER challenge

CMD ["tini", "--", "./warning"]