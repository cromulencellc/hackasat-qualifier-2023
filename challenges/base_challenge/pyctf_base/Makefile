
REGISTRY ?= has4/quals/challenges

.PHONY: build
build:
	docker build -t ${REGISTRY}/ctfpythonbase:latest ./pyctf/
	docker build --file=images/python.dockerfile -t ${REGISTRY}/ctfpython:latest .
	docker build --file=images/bsk.dockerfile -t ${REGISTRY}/ctfbsk:latest .
	docker build --file=images/gnuradio.dockerfile -t ${REGISTRY}/ctfgrchallenge:latest .
	docker build --file=images/phasedarray.dockerfile -t ${REGISTRY}/ctfphasedarray:latest .
	docker build --file=images/gmat.dockerfile -t ${REGISTRY}/ctfgmat:latest .

	docker tag ${REGISTRY}/ctfpython:latest has4/quals/challenges/challenge/pychallenge:latest
	docker tag ${REGISTRY}/ctfbsk:latest has4/quals/challenges/challenge/bskchallenge:latest

.PHONY: gr
gr:
	docker build --file=images/gnuradio.dockerfile -t has4/quals/challenges/challenge/ctfgrchallenge:latest .

