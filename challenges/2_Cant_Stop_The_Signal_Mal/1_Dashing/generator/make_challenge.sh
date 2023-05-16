#!/bin/sh

# generate morse audio
/bin/bash -c "python3 morsegen.py" > /dev/null

# # tell the uploader what files we want uploaded
echo "\nUpload generated files:"
echo "/mnt/beepboop.wav" | /upload/upload.sh