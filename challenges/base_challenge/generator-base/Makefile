REGISTRY ?= has4/quals


.PHONY: base
base:
	docker build . -t generator-base:debug
	docker tag generator-base:debug generator-base:latest
	docker tag generator-base:debug ${REGISTRY}/generator-base/generator-base:latest