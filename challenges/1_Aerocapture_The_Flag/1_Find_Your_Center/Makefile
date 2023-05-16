CHAL_NAME ?= center
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:challenge
challenge:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	#socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/${CHAL_NAME}\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver
