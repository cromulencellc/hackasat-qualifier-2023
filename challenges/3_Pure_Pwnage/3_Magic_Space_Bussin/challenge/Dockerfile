FROM has4/quals/challenges/magic_space_bus:static as binary
# FROM magic_space_bus:static as binary

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt -y update && apt -y upgrade && apt -y install \
    tini

WORKDIR /challenge/
COPY run.sh /challenge/
COPY --from=binary /magic/magic /challenge/

RUN chmod +x run.sh

# Add less privledged user and change to them
RUN groupadd -r --gid=1000 challenge && \
    useradd -m -r -s /bin/bash -g challenge --uid=1000 challenge && \
    chown -R 1000:1000 /challenge/

USER challenge

WORKDIR /challenge

ENTRYPOINT [ "tini", "--", "/challenge/run.sh" ]
