FLAG ?= flag{SCRUBBEDFlagWithSomeSpecialExtraNess!!!!}
REGISTRY ?= has4/quals/challenges/spectre

.PHONY:solver_genonly
solver_genonly:
	docker run -v $(PWD)/exespace/:/data -it $(REGISTRY):solver_pre
.PHONY:solver_postonly
solver_postonly:
	docker run -v $(PWD)/exespace/:/data -it $(REGISTRY):solver_post
.PHONY:solver
solver:
	docker run -v $(PWD)/exespace/:/data -it $(REGISTRY):solver_pre
	docker run --cpuset-cpus="3" -v $(PWD)/exespace/:/data -e FLAG=$(FLAG) -it $(REGISTRY):challenge
	docker run -v $(PWD)/exespace/:/data -it $(REGISTRY):solver_post

.PHONY:build
build:
	docker build static -t $(REGISTRY):static
	docker build challenge -t $(REGISTRY):challenge
	docker build solver -f=solver/pre.dockerfile -t $(REGISTRY):solver_pre
	docker build solver -f=solver/post.dockerfile -t $(REGISTRY):solver_post
.PHONY:static
static:
	docker build static -t $(REGISTRY):static
	docker run -v $(PWD)/:/data/ -it $(REGISTRY):static

.PHONY: helper
helper:
	docker build helper -t helper
	docker run -v $(PWD)/helper:/data helper