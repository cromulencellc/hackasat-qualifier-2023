#!/bin/sh

docker pull has4/quals/challenges/as-below:challenge
docker pull has4/quals/challenges/as-below:solver

docker tag has4/quals/challenges/as-below:challenge as-below:challenge
docker tag has4/quals/challenges/as-below:solver as-below:solver