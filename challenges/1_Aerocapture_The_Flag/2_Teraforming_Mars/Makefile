
REGISTRY ?= has4/quals/challenges/mars
LCM_PORT ?= 8000
CHAL_PORT ?= 5000
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{SCRUBBED}

.PHONY:build
build:
	docker build challenge -t $(REGISTRY):challenge
	docker build solver -t $(REGISTRY):solver

.PHONY:challenge
challenge:
	#socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -p ${LCM_PORT}\:8080 -e SERVICE_PORT=${LCM_PORT} -e SERVICE_HOST=localhost -e FLAG=flag{TESTflag1234} $(REGISTRY)\:challenge" > log 2>&1 &
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -p ${LCM_PORT}\:8080 -e SERVICE_PORT=${LCM_PORT} -e SERVICE_HOST=localhost -e FLAG=${FLAG} has4/quals/challenges/mars\:challenge" > log 2>&1 &
	echo "nc localhost $(CHAL_PORT) to play"


.PHONY:solver
solver:
	docker run --rm -it -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${REGISTRY}:solver
