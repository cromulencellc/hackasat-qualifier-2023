#!/bin/sh

# create the flag file
/bin/bash -c "echo -n -e \"\x01\x23\x45\x67\x89\xab\xcd\xef${FLAG}\" > flag"

# generate symbols with gnuradio
/bin/bash -c "python3 qam.py" > /dev/null

# tell the uploader what files we want uploaded
echo "/generator/symbols"