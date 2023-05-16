CHAL_NAME ?= tle
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:challenge
challenge:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	make challenge
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY: challenge_ci
challenge_ci:
	docker pull has4/quals/challenges/tle\:challenge
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/tle\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY: solver_ci
solver_ci:
	docker pull has4/quals/challenges/tle\:challenge
	docker pull has4/quals/challenges/tle\:solver
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/tle\:challenge" > log 2>&1 &
	docker run -e CHAL_HOST=$(CHAL_HOST) -e CHAL_PORT=$(CHAL_PORT) has4/quals/challenges/tle\:solver
