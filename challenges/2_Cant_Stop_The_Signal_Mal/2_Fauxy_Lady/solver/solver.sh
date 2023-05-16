#!/bin/sh

# gnuradio solver
echo "Running gnuradio solver"
/bin/bash -c "python3 solver.py"

# cat flag
echo ""
/bin/bash -c "cat data"
echo "\n"