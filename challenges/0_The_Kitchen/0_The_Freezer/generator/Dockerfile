FROM ubuntu:18.04

WORKDIR /generator
COPY --from=has4/quals/generator-base/generator-base:latest /upload/ /upload
ADD make_challenge.sh /generator/

CMD ["/bin/bash", "-c", "sh make_challenge.sh | /upload/upload.sh"]
