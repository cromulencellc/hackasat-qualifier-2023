#!/bin/bash

rm -rf magic_public
mkdir -p magic_public/static
mkdir -p magic_public/challenge

# Copy Static Files
cp -r static/bus magic_public/static
cp static/build.sh magic_public/static
cp static/main.cpp magic_public/static
cp static/CMakeLists.txt magic_public/static
cp static/Dockerfile magic_public/static/Dockerfile

# Copy Challenge Files
cp challenge/Dockerfile_Public magic_public/challenge/Dockerfile
cp challenge/malloc.c magic_public/challenge
cp challenge/run.sh magic_public/challenge

cp static/Makefile_Public magic_public/Makefile

tar czf magic_public.tar.gz magic_public