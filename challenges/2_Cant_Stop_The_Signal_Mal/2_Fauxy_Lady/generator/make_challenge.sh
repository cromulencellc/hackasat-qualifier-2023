#!/bin/sh

# create the flag file
#/bin/bash -c "echo -n -e \"\x01\x23\x45\x67\x89\xab\xcd\xef${FLAG}\" > flag"

# generate packet
/bin/bash -c "python3 packets.py" > /dev/null

# generate signal
/bin/bash -c "python3 satsig.py" > /dev/null

# tell the uploader what files we want uploaded
echo "/generator/signal.wav"