#!/usr/bin/python3 -u

import os
import random
import signal
import sys
from base64 import b64decode
from hashlib import sha256
from pathlib import Path
from subprocess import Popen, PIPE

def alarm_handler(signum, frame):
    print("timed out, sorry")
    exit(1)
signal.signal(signal.SIGALRM, alarm_handler)

input_timeout = int(os.environ.get('INPUT_TIMEOUT', 30))
crash_timeout = int(os.environ.get('CRASH_TIMEOUT', 5))
wait_timeout = int(os.environ.get('WAIT_TIMEOUT', 1))

bin_paths = [c for c in Path('/challenge/as-below').iterdir() if '' == c.suffix]
all_bins = list(bin_paths)

# change this sample size when it's not just a singleton
picked = random.sample(all_bins, 10)

print("binary_name\tsha256\nsend your solution as base64, followed by a newline", flush=True)

for c in picked:
    hash = sha256()
    with open("as-below/" + c.name, 'rb') as f:
        while b'' != (got := f.read(1024)):
            hash.update(got)

    print("{}\t{}".format(c.name, hash.hexdigest()), flush=True)
    signal.alarm(input_timeout)
    try: 
        answer =   input() 
        candidate = b64decode(answer)
    except:
        print("Bad input")
        sys.exit(-1)
    signal.alarm(0)
    
    signal.alarm(crash_timeout)
    proc = Popen(["wasmer", str(c)],
                 stdin=PIPE, stdout=PIPE, stderr=PIPE)
    (out, err) = proc.communicate(candidate)
    signal.alarm(0)
    if 0 != proc.returncode:
        print("didn't exit happy, sorry", flush=True)
        exit(-1)
    
    proc.wait(wait_timeout)

flag = os.environ.get('FLAG', "flag{ERROR: CONTACT_ADMIN_IF_U_SEE_THIS}")
print("You did it - here's the flag")
print( flag , flush=True)
exit(0)