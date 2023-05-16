import argparse 
import setup 
import scipy.constants
#from phased_array import phased


import numpy as np
import phased_array.phased as phased

symbol_table = [ 1+1j, -1+1j, -1-1j, 1-1j]

def makeNoiseSignal(  N , A ):
    As =  A /np.sqrt(2)
    noise = As* np.random.randn( N ) + 1j*As*np.random.randn( N )
    return noise
def str_to_qpsk( strData ):

    byte_array = bytearray( strData )
    num_list = list( byte_array )
    symbol_list=[]
    for num in num_list: 
        for i in range(6,-2,-2):
            two_bit =( num >> i ) & 0x03 # Just take 2 bits bruh
            symbol = symbol_table[ two_bit ]
            symbol_list.append( symbol )
    return  symbol_list

def makeQpskSignal( bytes, M , Abytes  ):
    symbols =  str_to_qpsk(  bytes ) 
    symbolsRep = np.repeat( symbols ,  M )
    N = len(symbolsRep)
    S = ( Abytes * symbolsRep )
    return S

def main(  flag , rootLoc ):
    wavelength = scipy.constants.c / setup.RF_FREQ
    signalAz = 100
    signalEl = 25
    noiseAz = 100
    noiseEl = 21
    Asignal = 100
    Ajamma = 2500
    M = 2
    # Location s list
    locations = [ ]
    for N in setup.ANTENNA_N_GRID:
        for E in setup.ANTENNA_E_GRID:
            loc = ( E , N )
            locations.append( loc )
    
    # Generate the square grid of antennas
    
    print("Generating signal file")
    signal = makeQpskSignal( flag.encode('utf-8') , M,  Asignal )
    Nsamp = len(signal)
    noiseJammer = makeNoiseSignal( Nsamp , Ajamma )
    array = phased.Array2D( locations ,  N=Nsamp , M=2 , noiseVar=1.0) 
    array.add_signal( signal , signalAz, signalEl , 0 )
    array.add_signal( noiseJammer , noiseAz, noiseEl , 1 )
    
    # Make teh data
    outSignal = array.getOutput( )
    locTxt = f"Frequency: {setup.RF_FREQ} Hz\nAntenna Number,East (m),North (m)\n"


    for id,loc in enumerate(locations):
        # open a file
        fname = f"{rootLoc}/Receiver_{id}.bin"
        f = open( fname,  'wb')
        ## Write the file
        sig = outSignal[id]
        sig.tofile( f )
        # Close the file
        f.close()
        Emeters = loc[0] * wavelength 
        Nmeters = loc[1] * wavelength 
        locTxt += f"{id},{Emeters},{Nmeters}\n"

    f = open(f"{rootLoc}/antennas.txt","wt")
    f.write( locTxt )
    f.close()

    f = open(f"{rootLoc}/readme.txt","wt")
    f.write( "Im sending you the flag and only the flag....but its being jammed....please recover.\n")
    f.write( f"Symbol Table: {symbol_table}\n")
    f.write( f"Symbol rate is 1/{M} times the sample rate\n")
    f.write( "All flags follow format flag{YourFlagIsABunchOfAsciiHere!!!}\n")
    f.close()
        
if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--flag",required=True)
    a.add_argument("--loc",required=True)
    args = a.parse_args()
    main(  args.flag , args.loc)
    #
