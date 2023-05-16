FROM node:lts-buster-slim as builder

WORKDIR /viewer

COPY viewer/src /viewer/src
COPY viewer/czml /viewer/czml

COPY viewer/*.json viewer/*.sh viewer/*.js /viewer/

RUN npm install --production=false && \
    npm run build

FROM node:lts-buster-slim as prod
WORKDIR /viewer
COPY viewer/server/* /viewer/
RUN npm install --production

FROM has4/quals/challenges/ctfgmat:latest as gmat

ENV NODE_ENV=production
WORKDIR /challenge
RUN apt update -y && \
    apt install -y tini

COPY *.txt /challenge/

RUN pip3 install -r reqs.txt
COPY ./*.py /challenge/
COPY *.sh /challenge/

COPY ./gmat_scripts /challenge/gmat_scripts

WORKDIR /challenge/viewer


COPY --from=prod /viewer/node_modules /challenge/viewer/node_modules 
COPY --from=builder /viewer/dist /challenge/viewer/dist
COPY viewer/package.json /challenge/viewer/
COPY viewer/server/server.js /challenge/viewer/

WORKDIR /challenge/viewer/czml

COPY viewer/czml/satellite.template /challenge/viewer/czml/

WORKDIR /challenge
RUN useradd -ms /bin/bash challenge

RUN chown -R challenge /challenge/viewer
RUN chown -R challenge /challenge/
RUN chmod +x /challenge/startup.sh
USER challenge
EXPOSE 8080

CMD ["/usr/bin/tini", "--", "/challenge/startup.sh"]