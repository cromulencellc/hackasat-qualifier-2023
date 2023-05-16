CHAL_NAME ?= qam
REGISTRY ?= has4/quals/challenges

FLAG ?= flag{SCRUBBED}

.PHONY:build
build:
	docker build generator -t $(CHAL_NAME):generator
	docker build solver -t $(CHAL_NAME):solver

.PHONY: generator
generator:
	sudo rm -rf bin/*
	docker run -e FLAG=$(FLAG) $(CHAL_NAME):generator

.PHONY:solver
solver:
	docker run -it --rm -v $(PWD)/out:/out $(CHAL_NAME):solver

.PHONY:generator_ci
generator_ci:
	rm -rf out/symbols
	docker pull $(REGISTRY)/$(CHAL_NAME):generator
	docker run -it --rm -v $(PWD)/out:/out -e "FLAG=$(FLAG)" $(REGISTRY)/$(CHAL_NAME):generator

.PHONY:solver_ci
solver_ci:
	docker pull $(REGISTRY)/$(CHAL_NAME):solver
	docker run -it --rm -v $(PWD)/out:/mnt -e "DIR=/mnt" $(REGISTRY)/$(CHAL_NAME):solver
