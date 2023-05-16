import struct
import crc
import os
import random

# generate satellite telemetry packets

def write(data):
    with open("tx_stream", "wb") as binary_file:
        # Write bytes to file
        binary_file.write(data)

def main():
    flag = os.getenv("FLAG")
    flagChunks = [flag[i: i + 40] for i in range(0, len(flag), 40)]
    txStream = b''
    for chunk in flagChunks:   
        x1 = b'\x7e'
        src = "1AB-CDE"
        dst = "2FGHI-1"
        x2 = struct.pack('>14s',(src+dst).encode('utf-8'))
        x3 = b'\x03'
        x4 = b'\xF0'
        f = struct.pack('>80s',chunk.encode('utf-8'))
        x5 = crc.gen(x2 + x3 + x4 + f).to_bytes(2, 'big')
        x6 = x1
        fauxPkt = x1 + x2 + x3 + x4 + f + x5 + x6
        
        a = b'\x1a\xcf\xfc\x1d'
        bc = len(fauxPkt).to_bytes(2,'big')

        txPkt = a + bc + bc + fauxPkt
        idle = b'\xFF' * random.randrange(100,200)
        txStream += idle + txPkt

    idle = b'\xFF' * random.randrange(100,200)
    txStream += idle

    write(txStream)

if __name__ == '__main__':
    main()