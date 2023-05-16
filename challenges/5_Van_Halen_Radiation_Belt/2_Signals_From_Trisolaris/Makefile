REGISTRY  ?= has4/quals/challenges
CHAL_NAME ?= $(REGISTRY)/trisolaris
CHAL_PORT ?= 3000
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{FAKE_FLAG}

.PHONY: challenge
challenge:
	docker run -v $(PWD)/bin:/data/ $(CHAL_NAME):static
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e SERVICE_PORT=$(SERVICE_PORT) -e SEED=1465500232115169100 -e FLAG=${FLAG} ${CHAL_NAME}\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"
.PHONY: solver
solver:
	make challenge
	docker run -v $(PWD)/bin:/data -e CHAL_HOST=$(CHAL_HOST) -e CHAL_PORT=$(CHAL_PORT) $(CHAL_NAME):solver 
.PHONY: build
build:
	docker build -t $(CHAL_NAME):static static
	docker build -t $(CHAL_NAME):challenge challenge
	docker build -t $(CHAL_NAME):solver solver
