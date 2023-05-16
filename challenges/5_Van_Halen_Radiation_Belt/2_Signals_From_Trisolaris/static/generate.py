import argparse 
import stars
import starlist 
import scipy.constants
#from phased_array import phased


import numpy as np
import phased_array.phased as phased


def makeIQSignal( Fs , Fc , N , A ):
    t =(1/Fs) * np.arange( 0,N )
    S = A*np.exp( 1j*2*np.pi*Fc*t , dtype=np.complex64)
    return S 

def main(  ):
    Fs = 100.0e6
    Nsamp = 10000

    latDegrees = starlist.OBSERVATORY_LLA[0]
    lonDegrees = starlist.OBSERVATORY_LLA[1]
    altitudeMeters = starlist.OBSERVATORY_LLA[2]
    
    observationTime =starlist.OBSERVATION_TIME
    # Location s list
    locations = [ ]
    for N in starlist.ANTENNA_N_GRID:
        for E in starlist.ANTENNA_E_GRID:
            loc = ( E , N )
            locations.append( loc )

    nearCatalog = starlist.nearestStars( maxLightYears=starlist.MAX_DISTANCE_LY)    
    obs = stars.StarObservatory( latDegrees=latDegrees , longDegrees=lonDegrees , altitude=altitudeMeters, catalog=nearCatalog)
    N = len( starlist.STARS)
    
    # Verify the stars in the starlist are visible
    obs.verifyVisible(observationTime, starlist.STARS)
    # Print out the az el and distance for each star
    starTable = {} 
    for (starId,freq) in zip(starlist.STARS, starlist.FREQS):
        print(f"Generating files for star {starId}")
        alt,az,d = obs.getAzEl( starId, observationTime ) 
        print(f"Star {starId} is at Az: {az} El: {alt} Distance: {d.light_seconds()/(86400*365)}")

        starTable[ starId ] = (alt,az,d, freq)
    
    # Generate the square grid of antennas
    array = phased.Array2D( locations ,  N=Nsamp , M=len( starlist.STARS ) , noiseVar=1.0) 
    signalList = []
    print("Generating signal file")
    for idx, starId in enumerate( starTable.keys()  ):
        star = starTable[starId]
        az = star[1].degrees
        el = star[0].degrees
        freq = star[3]
        CarrierFreq = freq * Fs 
        signal = makeIQSignal( Fs , CarrierFreq , Nsamp , 10.0 )
        array.add_signal(signal , az , el, idx )
        #array.add_signal(signal , 163.3, 5.5, idx )
        signalList.append( signal )
        print(f"Adding {starId} at az: {az}, el: {el}") 
    # Make teh data
    outSignal = array.getOutput( )
    
    locTxt = "Antenna Number,East (m),North (m)\n"
    wavelength = scipy.constants.c / starlist.RF_FREQ

    for id,loc in enumerate(locations):
        # open a file
        fname = f"bin/Arecibo_{id}.bin"
        f = open( fname,  'wb')
        # Write the file
        sig = outSignal[id]
        sig.tofile( f )
        # Close the file
        f.close()
        
        #
        Emeters = loc[0] * wavelength 
        Nmeters = loc[1] * wavelength 
        locTxt += f"{id},{Emeters},{Nmeters}\n"

    f = open("bin/antennas.txt","wt")
    f.write( locTxt )
    f.close()

        
if __name__ == "__main__":

    main(  )
