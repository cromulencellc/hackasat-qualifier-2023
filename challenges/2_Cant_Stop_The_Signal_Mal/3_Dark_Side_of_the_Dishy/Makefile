CHAL_NAME ?= darkside
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build generator -t $(CHAL_NAME):generator
	docker build solver -t $(CHAL_NAME):solver
.PHONY: generator
generator:
	sudo rm -rf bin/*
	docker run -v $(PWD)/bin:/out/ -e FLAG=$(FLAG) $(CHAL_NAME):generator
.PHONY:solver
solver:
	sudo rm -rf bin/*
	make generate
	docker run --rm -i -v $(PWD)/bin:/out/ ${CHAL_NAME}:solver

.PHONY: generator_ci
generator_ci:
	sudo rm -rf bin/*
	docker pull $(REGISTRY)/$(CHAL_NAME):generator
	docker run -v $(PWD)/bin:/out/ -e FLAG=$(FLAG) $(REGISTRY)/$(CHAL_NAME):generator
.PHONY: solver_ci
solver_ci:
	docker pull $(REGISTRY)/$(CHAL_NAME):solver
	docker run -v $(PWD)/bin:/data/ -e FLAG=$(FLAG) $(REGISTRY)/$(CHAL_NAME):solver
