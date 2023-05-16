REGISTRY_HOST ?= has4/quals/challenges
CHAL_NAME ?= $(REGISTRY_HOST)/kalman-at-me-bro
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{FAKE_FLAG}

.PHONY: static
static:
	docker build static -t $(CHAL_NAME):static
	docker run -v $(PWD)/data:/binaries $(CHAL_NAME):static

.PHONY:build
build:
	docker build static -f static/Dockerfile_Public -t $(CHAL_NAME):base
	docker build static -t $(CHAL_NAME):static
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:challenge
challenge:
	#socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/kalman-at-me-bro\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	make challenge
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver
