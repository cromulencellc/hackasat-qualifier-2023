CHAL_NAME ?= dashing
REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

build: generator solver
testgen: generator generate
testsolve: solver solve
run: testgen testsolve

.PHONY:generator
generator:
	docker build generator -t $(REGISTRY)/$(CHAL_NAME):generator
	
.PHONY:solver
solver: 
	docker build solver -t $(REGISTRY)/$(CHAL_NAME):solver

.PHONY:generate
generate:
	rm -rf ./out/beepboop.wav
	docker run -it --rm -v $(PWD)/out:/mnt -e "FLAG=$(FLAG)" $(REGISTRY)/$(CHAL_NAME):generator

.PHONY:solve
solve:
	docker run -it --rm -v $(PWD)/out:/mnt -e "DIR=/mnt" $(REGISTRY)/$(CHAL_NAME):solver

.PHONY: generator_ci
generator_ci:
	sudo rm -rf out/*
	docker pull $(REGISTRY)/morse:generator
	docker run -it --rm -v $(PWD)/out:/mnt -e "FLAG=$(FLAG)" $(REGISTRY)/morse:generator

.PHONY: solver_ci
solver_ci:
	docker pull $(REGISTRY)/morse:solver
	docker run -it --rm -v $(PWD)/out:/mnt -e "DIR=/mnt" $(REGISTRY)/morse:solver
