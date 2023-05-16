#!/bin/bash

set -o errexit   # abort on nonzero exitstatus
set -o nounset   # abort on unbound variable
set -o pipefail  # don't hide errors within pipes

IMAGE_NAME=812205179049.dkr.ecr.us-east-2.amazonaws.com/has4-quals/leavenworth-street:challenge

image_name=${IMAGE_NAME:=leavenworth-street}
flag=${FLAG:="contact mission control if you see this placeholder flag"}
submission_path=${SUBMISSION_PATH:="../solver.js"}
seed=${SEED:=0}

container_name=$(docker create --rm --env "FLAG=${flag}" --env "SEED=${seed}" $image_name)
docker cp "$submission_path" "$container_name:/solver/solver.ts"
docker start --attach "$container_name"
