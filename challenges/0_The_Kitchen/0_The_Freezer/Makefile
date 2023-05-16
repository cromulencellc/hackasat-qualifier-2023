CHAL_NAME ?= basic_file

REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

build: generator solver

.PHONY:generator
generator:
	docker build generator -t $(CHAL_NAME):generator

.PHONY:solver
solver: 
	docker build solver -t $(CHAL_NAME):solver

.PHONY:test
test:
	rm -rf data/*
	docker run -it --rm -v $(PWD)/data:/out -e "FLAG=flag{FAKE_FLAG}" $(CHAL_NAME):generator
	docker run -it --rm -v $(PWD)/data:/mnt -e "DIR=/mnt" $(CHAL_NAME):solver
