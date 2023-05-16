CHAL_NAME ?= basic_handoff
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1
LCM_PORT ?= 7000

REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build challenge -t $(CHAL_NAME):challenge
	

.PHONY:challenge
challenge:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -p ${LCM_PORT}\:7000 -e SERVICE_PORT=${LCM_PORT} -e SERVICE_HOST=localhost -e FLAG=flag{TESTflag1234} ${CHAL_NAME}\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver
	echo "To connect: nc localhost $(CHAL_PORT)"
