FROM python:3.10-slim AS python_env

WORKDIR /src
RUN apt update ;\
    apt install -y --no-install-recommends python3-virtualenv python-dev build-essential
    
ENV VIRTUAL_ENV="/opt/venv"
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./

RUN python -m venv $VIRTUAL_ENV ;\
    pip install --upgrade pip ;\
    pip install --no-cache-dir -r requirements.txt


FROM python:3.10-slim
ENV VIRTUAL_ENV="/opt/venv"
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=python_env /opt/venv /opt/venv

WORKDIR /solver

ADD solver.py /solver/

CMD ["python", "solver.py","--msgs","/data/encrypted_msgs.txt","--dict","/data/word_dictionary.json"]
#CMD ["python", "solver.py","--v","True", "--msgs","encrypted_msgs.txt","--dict","word_dictionary.json"]