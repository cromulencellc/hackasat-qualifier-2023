CHAL_NAME ?= satsig
REGISTRY ?= has4/quals/challenges
FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build generator -t $(CHAL_NAME):generator
	docker build solver -t $(CHAL_NAME):solver

.PHONY:generator
generator:
	rm -rf out/signal.wav
	docker run -it --rm -v $(PWD)/out:/out -e "FLAG=$(FLAG)" $(CHAL_NAME):generator
.PHONY:solver
solver: 
	docker run -it --rm -v $(PWD)/out:/out $(CHAL_NAME):solver

.PHONY:generator_ci
generator_ci:
	docker pull $(REGISTRY)/$(CHAL_NAME):generator
	rm -rf out/signal.wav
	docker run -it --rm -v $(PWD)/out:/out -e "FLAG=$(FLAG)" $(REGISTRY)/$(CHAL_NAME):generator

.PHONY:solver_ci
solver_ci:
	rm -rf solver/data
	docker pull $(REGISTRY)/$(CHAL_NAME):solver
	docker run -it --rm -v $(PWD)/out:/out $(REGISTRY)/$(CHAL_NAME):solver
