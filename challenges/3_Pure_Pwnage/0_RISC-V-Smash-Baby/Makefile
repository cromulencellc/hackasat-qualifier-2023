CHAL_NAME ?= riscv_smash
REGISTRY ?= has4/quals/challenges
#has4/quals/challenges/risc-v-smash-baby:challenge
FLAG ?= flag{FAKE_FLAG}

CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

.PHONY:build
build:
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:static
static:
	sudo rm -rf ./static/*
	docker run -it -v ./static:/out $(REGISTRY)/$(CHAL_NAME):challenge /bin/bash -c "cp /server/smash-baby /out"
	sudo chown -R ${USER}:${USER} static

.PHONY:challenge
challenge:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	#echo "To connect: nc localhost $(CHAL_PORT)"
.PHONY:solver
solver:
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	docker run --rm -it -e CHAL_HOST=$(CHAL_HOST) -e CHAL_PORT=$(CHAL_PORT) $(CHAL_NAME):solver
