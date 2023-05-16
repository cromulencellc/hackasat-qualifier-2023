FROM denoland/deno:debian AS builder

RUN apt-get update && \
  apt-get install -y curl git doas && \
  curl -fsSL https://crystal-lang.org/install.sh | bash

RUN mkdir /chall
WORKDIR /chall

RUN addgroup chall --gid 1000 && \
  adduser --disabled-password --uid 1000 --ingroup chall --home /chall chall && \
  chown -R chall:chall /chall 
USER chall:chall

COPY --chown=chall:chall shard.* /chall/
RUN shards install

COPY --chown=chall:chall . /chall

RUN shards build leavenworth

FROM denoland/deno:debian
RUN apt-get update && \
  apt-get install -y curl git doas && \
  curl -fsSL https://crystal-lang.org/install.sh | bash

RUN mkdir -p /chall/bin /solver
WORKDIR /chall

COPY --chown=root:root ./doas.conf /etc/doas.conf
RUN chmod go-wx /etc/doas.conf

RUN addgroup chall --gid 1000 && \
  adduser --disabled-password --uid 1000 --ingroup chall --home /chall chall && \
  chown -R chall:chall /chall /solver
USER chall:chall

COPY --chown=chall:chall --from=builder /chall/bin/leavenworth /chall/bin/leavenworth
COPY --chown=chall:chall vendor.ts /chall/vendor.ts

RUN doas -n -u deno /usr/bin/deno run --allow-all vendor.ts

CMD /chall/bin/leavenworth
