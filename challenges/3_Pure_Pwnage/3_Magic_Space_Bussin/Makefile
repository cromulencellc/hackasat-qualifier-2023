REGISTRY_HOST ?= has4/quals/challenges
CHAL_NAME ?= $(REGISTRY_HOST)/magic_space_bus
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{FAKE_FLAG}

.PHONY: static
static:
	sudo rm -rf data/*
	docker build static -t $(CHAL_NAME):static
	docker run -v $(PWD)/data:/binaries $(CHAL_NAME):static
	sudo rm -rf static/magic
	sudo cp data/magic static/
	sudo chown ${USER}:${USER} static/magic

.PHONY:build
build:
	docker build static -t $(CHAL_NAME):static
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:challenge
challenge:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=flag{TESTflag1234} ${CHAL_NAME}\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"

.PHONY:solver
solver:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=flag{TESTflag1234} ${CHAL_NAME}\:challenge" > log 2>&1 &
	docker run --rm -i -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} ${CHAL_NAME}:solver
	echo "To connect: nc localhost $(CHAL_PORT)"

# Please keep in mind that the binary was manually copied (and checked) from the docker container into
# the folder made
.PHONY:public
public:
	./make_public.sh

