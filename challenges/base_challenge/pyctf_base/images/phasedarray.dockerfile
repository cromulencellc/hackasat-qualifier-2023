FROM has4/quals/challenges/ctfpython:latest

USER root

COPY --from=has4/quals/challenges/ctfphasebase:latest /package/dist/*.whl /ctf/
RUN pip3 install /ctf/phased_array*.whl

USER chal
