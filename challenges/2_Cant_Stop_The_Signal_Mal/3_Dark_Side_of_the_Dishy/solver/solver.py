import argparse as ap
import scipy
import csv
import numpy as np
import matplotlib.pyplot as plt
import beamformer
symbol_table = [ 1+1j, -1+1j, -1-1j, 1-1j]

def adaptive(  pilots , signals ):
    nPilots = len( pilots )
    p = np.transpose( np.matrix( pilots )  ) 
    Y = np.matrix( signals[:nPilots,:] )   
    w = np.linalg.inv( Y.H @ Y ) @ Y.H @ p 
    return w 

def symbols_to_str( qpsk , reps):
    qpsk = qpsk[::reps]

    hardSymbols =   np.sign(np.real(qpsk)) + 1j * np.sign(np.imag(qpsk))
    binArray = [ ]
    for symbol in np.asarray( hardSymbols).flatten().tolist():
        binary = symbol_table.index( symbol )
        binArray.append( binary )
    byte = 0
    bits_written = 0
    byteList = []
    for value in binArray:
        byte = byte << 2 | value 
        bits_written += 2
        if( bits_written == 8 ):
            byteList.append( byte )
            byte=0
            bits_written = 0 
    o = "".join([chr(a) for a in byteList ])
    return o

def str_to_qpsk( strData , reps):
    bdata = strData.encode( )
    byte_array = bytearray( bdata )
    num_list = list( byte_array )
    symbol_list=[]
    for num in num_list: 
        for i in range(6,-2,-2):
            two_bit =( num >> i ) & 0x03 # Just take 2 bits bruh
            symbol = symbol_table[ two_bit ]
            symbol_list.append( symbol )
    symbolRepd = np.repeat( symbol_list , reps )
    return symbolRepd

def apply_beamformer( S , w ):
    out = S @ w 
    # Apply scale to unity
    
    return out / np.max( np.abs( out ))
def solve( fileloc , fileprefix ):
    rf = 500000000
    wavelength = scipy.constants.c / rf 
    # load the antenna locations
    locations = []
    antennaNums = []
    with open(f"{fileloc}/antennas.txt", "r") as csvfile:
        next(csvfile)

        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            
            E_wv = float(row["East (m)"]) / wavelength
            N_wv =  float(row["North (m)"]) / wavelength
            idx = int(row["Antenna Number"])
            loc = ( E_wv, N_wv ) 
            locations.append(loc)
            antennaNums.append( idx )
    L = len(locations )
    # find the size of the signal
    exampleSignal = np.fromfile( f"{fileloc}/{fileprefix}_0.bin" , dtype=np.complex64)
    N = len( exampleSignal )
    # load the signal files
    signals = np.zeros( (L,N) , dtype=np.complex64 )
    #for idx in antennaNums:
    for idx in range( 0 ,L ):
        fname = f"{fileloc}/{fileprefix}_{idx}.bin"
        signal = np.fromfile( fname , dtype=np.complex64)
        signals[idx] = signal

    signals = np.transpose(  np.matrix( signals )  ) 


    # This signal is so frickin strong - lets do beamformer beam forming
    flagQpsk = str_to_qpsk("flag{" , 2 ) 
    
    w_adaptive = adaptive( flagQpsk , signals )
    # Dont do any steering
    w_nosteer  = np.matrix( np.ones( ( w_adaptive.shape )) ) / len( w_adaptive)
    # try mvdr ---assume we know where to look
    R = beamformer.spatial_covariance( signals , 100)
    p,w_mvdr  = beamformer.mvdr_2d( np.linalg.inv(R), 100,25, locations ) 
    # Do the adaptive algo - its the best
    w_adaptive = adaptive( flagQpsk , signals )
    n  = apply_beamformer( signals , w_nosteer )
    m  = apply_beamformer( signals , w_mvdr )
    a  = apply_beamformer( signals , w_adaptive )
    plt.plot( np.real(n), np.imag(n) , 'r.')
    plt.plot( np.real(m), np.imag(m) , 'g.')
    plt.plot( np.real(a), np.imag(a) , 'b.')
    plt.show()
    o = symbols_to_str(a ,reps=2)
    print( o )
if __name__ == "__main__":
    a = ap.ArgumentParser()
    a.add_argument("--path", required=True)
    a.add_argument("--prefix",required=True)
    args = a.parse_args() 
    solve(args.path, args.prefix)
    