#!/bin/bash

set -o errexit   # abort on nonzero exitstatus
set -o nounset   # abort on unbound variable
set -o pipefail  # don't hide errors within pipes
set -o xtrace    # show expanded commands

image_name=${IMAGE_NAME:=SCRUBBED.amazonaws.com/has4-quals/spectrel:challenge}
flag=${FLAG:="contact mission control if you see this placeholder flag"}
submission_path=${SUBMISSION_PATH:="../solver.js"}
seed=${SEED:=0}

workdir=${submission_path}.workdir
submission_bz=${workdir}/submission.bz2

echo $SUBMISSION_PATH
echo $workdir
echo "hello again"

mkdir -p ${workdir}
cp ${submission_path} ${submission_bz}
container_name=$(docker create --env "FLAG=${flag}" --env "SEED=${seed}" --volume ${workdir}/:/data $image_name)
docker logs $container_name
docker start --attach "$container_name"
cp ${workdir}/out.bz2 $(dirname $submission_path)/stdout