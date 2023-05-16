#!/bin/bash

pushd phased_array_base/phased_array
make build
popd

pushd generator-base
make
popd


cd pyctf_base
make build
