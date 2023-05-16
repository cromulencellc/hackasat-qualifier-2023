#!/bin/bash

rm -rf warning_public
mkdir -p warning_public/static
mkdir -p warning_public/challenge

# Copy Static Files
cp static/build.sh warning_public/static
cp static/main.cpp warning_public/static
cp static/CMakeLists.txt warning_public/static
cp static/Dockerfile warning_public/static/Dockerfile

# Copy Challenge Files
cp challenge/Dockerfile_Public warning_public/challenge/Dockerfile
cp challenge/run.sh warning_public/challenge

cp static/Makefile_Public warning_public/Makefile

tar czf warning_public.tar.gz warning_public
