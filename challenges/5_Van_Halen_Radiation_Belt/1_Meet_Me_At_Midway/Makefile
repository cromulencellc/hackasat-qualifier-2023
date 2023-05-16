CHAL_NAME ?= meetmeatmidway
CHAL_PORT ?= 12345
CHAL_HOST ?= 172.17.0.1

FLAG ?= flag{FAKE_FLAG}

.PHONY:build
build:
	docker build challenge -t $(CHAL_NAME):challenge
	docker build solver -t $(CHAL_NAME):solver

.PHONY:challenge
challenge:
	docker pull has4/quals/challenges/meetmeatmidway\:challenge
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/meetmeatmidway\:challenge" > log 2>&1 &
	echo "To connect: nc localhost $(CHAL_PORT)"
	
.PHONY:solver
solver: 
	docker pull has4/quals/challenges/meetmeatmidway\:solver
	docker pull has4/quals/challenges/meetmeatmidway\:challenge
	socat -v tcp-listen:$(CHAL_PORT),reuseaddr exec:"docker run --rm -i -e FLAG=${FLAG} has4/quals/challenges/meetmeatmidway\:challenge" > log 2>&1 &
	docker run --rm -it -v $(PWD)/static:/data -e CHAL_HOST=${CHAL_HOST} -e CHAL_PORT=${CHAL_PORT} has4/quals/challenges/meetmeatmidway\:solver
