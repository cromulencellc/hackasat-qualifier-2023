import sys
sys.path.append("solver")

from pwn import *
import argparse
import numpy as np

import mvdr
import csv
import scipy 
import matplotlib.pyplot as plt
from matplotlib import cm
from findpeaks import findpeaks
import stars 
import datetime
import pytz

context.log_level = 'debug'

from skimage.feature import peak_local_max 

from alive_progress import alive_bar

def run( hostname , port , file_dir ):
    rf = 10.0e9 
    
    wavelength = scipy.constants.c / rf 
    dataLoc = file_dir
    # load the antenna locations
    locations = []
    antennaNums = []
    with open(f"{dataLoc}/antennas.txt", "r") as csvfile:
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

    exampleSignal = np.fromfile( f"{dataLoc}/Arecibo_0.bin" , dtype=np.complex64)
    N = len( exampleSignal )
    # load the signal files
    signals = np.zeros( (L,N) , dtype=np.complex64 )
    for idx in antennaNums:
        fname = f"{dataLoc}/Arecibo_{idx}.bin"
        signal = np.fromfile( fname , dtype=np.complex64)
        signals[idx] = signal  
    
    # First solve the az and els of the transmitters
    Nsnapshot = 100
    Rhat = mvdr.spatial_covariance( signals , Nsnapshot)
    az_search = np.arange( 0 , 360 , 1 )
    el_search = np.arange( 0, 90 , 1 )
    R_inv = np.linalg.inv( Rhat )
    eigs = np.linalg.eig( Rhat )
    P = np.zeros( (len(az_search) , len(el_search)) , dtype=np.float32)
    print("Generating MVD spectrum")
    with alive_bar( len(az_search)) as bar:

        for k,az in enumerate(az_search):
            for z,el in enumerate( el_search ):
                pow,w = mvdr.mvdr_2d( R_inv, az,el , locations )
                P[k][z] = pow 
            bar()
    # Find the peaks and associate each one with a star
    peaks = peak_local_max(P, min_distance=1 , num_peaks=5)
    

        


    # Plot the eigenvectors
    fig =  plt.figure(1)
    plt.stem( eigs[0] )
    fig = plt.figure(2)
    plt.plot( signals[1,:])
    # Plot the mvdr spectrum 
    fig = plt.figure(3)
    AZ,EL =np.meshgrid( az_search,el_search )
    plt.contourf( az_search,el_search, P.transpose() )
     

    plt.xlabel("Azimuth (degrees)")
    plt.ylabel("Elevation (degrees)")

    plt.show()


    # Handle connecting
    r = remote( hostname , port )
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline( ticket )
    
    
    # Get the Max distance of the trisolaran empire from earth
    r.recvuntil(b"empire is within", drop=True)
    LYstr = r.recvuntil(b"light years", drop=True)
    ly = float( LYstr )
    # Get the time of recv
    r.recvuntil(b"received at: ", drop=True)
    tStr = r.recvuntil(b"UTC", drop=True)
    # Get location of the array
    r.recvuntil("Latitude:", drop=True)
    latStr = r.recvuntil("deg", drop=True)
    r.recvuntil("Longitude:")
    lomStr = r.recvuntil("deg", drop=True)
    r.recvuntil("Altitude:", drop=True)
    altStr = r.recvuntil("m", drop=True)
    # Get the Frequency of the signal 
    r.recvuntil("at:", drop=True)
    fStr = r.recvuntil("HZ", drop=True)
    # verify this freq against what we use for the phased array!

    # move this to use data mined from the chal 
    lat = float( latStr )#18.3464 
    lon= float( lomStr)
    alt  =float( altStr)
    timeOfView = datetime.datetime.strptime( tStr.decode().strip() , "%Y-%m-%d %H:%M:%S" )

    timeOfView =  timeOfView.replace(tzinfo=pytz.UTC)

    v = stars.Viewer( lat , lon , alt , ly )
    v.observe_at( timeOfView )
    print("Trying to associate peaks with stars")
    starField = []
    for peak in peaks:
        az = peak[0]
        el = peak[1]
        out = v.nearest( az,el ,5 )
        starNumber =  list(out.keys())[0]
        distance = v.get_distance( starNumber ) 
        starField.append( ( starNumber , distance ) )

    starField.sort(key = lambda x: x[1].au)
    starList = [ star[0] for star in starField ]
    print(f"I think the stars are {starField}")
    
    # Now enter the numbers
    r.recvuntil("originate?")
    firstStar = f"{starList[0]}"
    r.sendline(firstStar.encode())
    r.recvuntil("stars?")
    starsStrings = [str(s) for s in starList]
    last4Stars = ",".join( starsStrings[1:])
    r.sendline(last4Stars.encode())
    out = r.recvuntil("Bye")
    print(out)




if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--hostname", required=True)
    a.add_argument("--port",required=True)
    a.add_argument("--filePath",required=True)
    args = a.parse_args()
    run( args.hostname , args.port , args.filePath )
    #run('localhost',3000,"bin/bin")
