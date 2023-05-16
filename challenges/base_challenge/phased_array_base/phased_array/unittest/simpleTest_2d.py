import sys
from unittest import TestCase
from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
import scipy.constants
from scipy.spatial.transform import Rotation as R
import csv
sys.path.append('phased_array')

import matplotlib.pyplot as plt
from matplotlib import cm

from alive_progress import alive_bar


import phased
import assertions
import numpy as np
import mvdr
import ut_tx

import time 


def columnRotHelper( axis , angle ):
    return np.squeeze(R.from_euler( axis, [angle],degrees=True).as_matrix()).transpose()


X_RANGE = np.arange(-2,2,0.25)
Y_RANGE = np.arange(-2,2,0.25)




def azElToWaveDelay( azDegrees, elDegrees , locations ):
    azRot = columnRotHelper("x", -azDegrees )
    elRot = columnRotHelper("y",-(90.0-elDegrees))
    UEN_2_LOS = np.matmul( elRot,  azRot )
    LOS_2_UEN  = UEN_2_LOS.transpose()
    los_LOS_Frame = np.array( [1,0,0] )
    los_UEN_FRAME = np.matmul( LOS_2_UEN , los_LOS_Frame )
    waveDistances = np.dot( locations , los_UEN_FRAME) # wavelengths
    return waveDistances
def beam_pattern_2d( locations , steerAz , steerEl ):
    xLocs = LOCATIONS_2D[0].flatten()
    yLocs = LOCATIONS_2D[1].flatten()
    shifts = []


    # Calculate element location vectors in U-E-N frame
    N = len(xLocs) * len(yLocs)
    k=0
    locationList = np.zeros(( N,3))
    for X in xLocs:
        for Y in yLocs:
            E = X
            N = Y
            Loc_UEN = np.array([0 , E , N])
            Loc_UEN.shape = (1,3)
            locationList[k] = Loc_UEN
            k = k+1
    # Calculate Steering stuff
    waveDelaySteering = azElToWaveDelay( steerAz , steerEl , locationList )
    wavePhasesSteering = -waveDelaySteering * np.pi * 2.0

    # Calculate power at every az/el
    azRange = np.arange(0,360,1)
    elRange = np.arange(0,90,1)
    Power = np.zeros( ( len(azRange), len(elRange) )) 
    #azRange = [270]
    #elRange = [0]
    azIndex = 0
    for az in azRange:
        elIndex =0 
        for el in elRange:
            waveDelayPhysics = azElToWaveDelay( az , el , locationList )
            wavePhases = waveDelayPhysics * np.pi * 2.0 #radians
            cpxPhasorPhysics = np.exp( 1j * wavePhases )
            cpxPhasorSteering = np.exp( 1j * wavePhasesSteering )
            summation = np.sum( cpxPhasorPhysics * cpxPhasorSteering )
            power = summation * np.conj( summation )
            Power[azIndex][elIndex] = power
            elIndex+=1
        azIndex+=1
    # Plot the result

    im = plt.contourf(azRange, elRange, Power.transpose())
    #fig.colorbar(im )

    plt.show()
def mvdr_2d_spectrum( locations ,signals ):
    az_search = np.arange( 0 , 360 , 1 )
    el_search = np.arange( 0, 90 , 1 )
    L = signals.shape[0]
    N = signals.shape[1]
    X  = []

    Nsnaps = 100#L * 4 # should be a multiple of L
    # Estimate the measurement covariance matrix based on the data.
    Rhat =  mvdr.spatial_covariance( signals , Nsnaps )
    R_inv = np.linalg.inv( Rhat )
    eigs = np.linalg.eig( Rhat )
    P = np.zeros( (len(az_search) , len(el_search)) , dtype=np.float32)
    for k,az in enumerate(az_search):
        for z,el in enumerate( el_search ):
            pow,w = mvdr.mvdr_2d( R_inv, az,el , locations )
            P[k][z] = pow 
    return az_search,el_search,P,eigs[0]
        
def solve_2d( ): 
    # Create the signals 
    Fs = 10.0e9
    freq = 100e6
    Nsamps = 100
    t = (1/Fs) * np.arange( 0 , Nsamps)
    F1  = Fs/10
    F2 = Fs/20
    F3 = Fs/15
    sig1 = 10.0 * np.exp( 1j*(2*np.pi*t*F1))
    sig2 = 10.0 * np.exp( 1j*(2*np.pi*t*F2))
    sig3 = 10.0 * np.exp( 1j*(2*np.pi*t*F3))

    LOCATIONS_2D = []
    for E in X_RANGE:
        for N in Y_RANGE:
            LOCATIONS_2D.append( (E,N))

    array = phased.Array2D( LOCATIONS_2D , N=Nsamps , M=3 , noiseVar =0.00001 )    
    array.add_signal( sig1 ,  90.0 , 10.0 , 0 )
    array.add_signal( sig2 ,  120.0 , 70.0, 1 )
    array.add_signal( sig3 ,  265.0 , 30.0, 2 )
    

    signal = array.getOutput( )

    #aoa,power = simple_1d( elementLocations , signal , rf )
    az,el,power,eigs = mvdr_2d_spectrum( LOCATIONS_2D, signal )
    # Plot all results 

    # Pull in the signal files
    plt.figure(2)
    plt.plot(  signal.transpose())

    plt.figure(3)
    plt.stem( np.real( eigs ) ) 


    fig = plt.figure(1)
    AZ,EL = np.meshgrid( az,el)
    #ax = plt.axes(projection ='3d')
    #im = ax.plot_surface(AZ, EL, power.transpose() ,cmap=cm.coolwarm,linewidth=0)
    plt.contourf( az,el, power.transpose() )
    plt.xlabel("Azimuth (degrees)")
    plt.ylabel("Elevation (degrees)")

    plt.show()



if __name__ == "__main__":
    #beam_pattern_1d(LOCATIONS,135)
    #beam_pattern_2d( LOCATIONS_2D ,100,45)
    solve_2d() 