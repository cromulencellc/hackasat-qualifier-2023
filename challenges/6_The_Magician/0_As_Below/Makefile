CHAL_NAME ?= as_below
CHAL_PORT ?= 5000
CHAL_HOST ?= 172.17.0.1
REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

.PHONY:runner
runner:
	cp static/as-below.tar.bz2 runner/
	docker build runner -t $(CHAL_NAME):runner
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e SEED=1465500232115169100 -e FLAG=flag{TESTflag1234} ${CHAL_NAME}\:runner" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	cp static/hints.json solver/
	docker build solver -t $(CHAL_NAME):solver
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e SEED=1465500232115169100 -e FLAG=flag{TESTflag1234} ${CHAL_NAME}\:runner" > log 2>&1 &
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver

.PHONY:build
build:
	rm -rf static/*
	docker build challenge -t $(CHAL_NAME):builder
	docker run -it -v `pwd`/static:/out $(CHAL_NAME):builder bash -c "ruby generate.rb; mv as-below.tar.bz2 hints.json /out"

.PHONY: dev
dev:
	docker build -f Dockerfile-dev -t ominous-etude-dev .
	docker run --rm -it -v $(shell pwd):/mnt --security-opt seccomp=unconfined --cap-add SYS_PTRACE ominous-etude-dev

