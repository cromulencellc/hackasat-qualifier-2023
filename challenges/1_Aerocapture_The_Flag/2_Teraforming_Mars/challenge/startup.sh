#!/bin/bash
cd /challenge/
cd viewer
/usr/local/bin/node server.js  > npmlog.txt&  
cd /challenge
python3 challenge.py
cp viewer/czml/satellite.czml viewer/dist/czml
if [ -z $TIMEOUT ]; then
    echo "Trajectory viewer up for 300 s "
    sleep 300
else
    echo "Trajectory viewer up for $TIMEOUT s"
    sleep $TIMEOUT
fi