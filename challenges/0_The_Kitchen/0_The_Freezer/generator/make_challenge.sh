#!/bin/sh

# create the flag file
echo $FLAG > flag.txt

# create the challenge file
tar jfc /tmp/flag.tar.bz2 flag.txt

# tell the uploader what files we want uploaded
echo "/tmp/flag.tar.bz2"

