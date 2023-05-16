import sys
from unittest import TestCase
from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
import scipy.constants
from scipy.spatial.transform import Rotation as R

sys.path.append('phased_array')

import matplotlib.pyplot as plt


import phased
import assertions
import numpy as np

import ut_tx
import mvdr 
import time 


def columnRotHelper( axis , angle ):
    return np.squeeze(R.from_euler( axis, [angle],degrees=True).as_matrix()).transpose()


LOCATIONS = np.arange( -4,4.01,0.25)



def mvdr_1d_spectrum( locations , signals ):
    aoa_search = np.arange( 0 , 180 , 1 )
    L = signals.shape[0]
    N = signals.shape[1]
    X  = []

    Nsnaps = 100#L * 4 # should be a multiple of L
    # Estimate the measurement covariance matrix based on the data.
    Rhat =  mvdr.spatial_covariance( signals , Nsnaps )
    R_inv = np.linalg.inv( Rhat )
    eigs = np.linalg.eig( Rhat )
    P = []
    for aoa in aoa_search:
        pow,w = mvdr.mvdr_1d( R_inv, aoa , locations )
        P.append( pow )
    return aoa_search,P,eigs[0]
        




def beam_pattern_1d( locations  , steerTo):
    # shifter values
    shifts = []
    for loc in locations:
        D = loc * np.cos( np.radians( steerTo ))
        phase = -D * np.pi * 2.0 
        shifts.append( phase  )
    phaseSteering = np.array( shifts  )
    cpxPhaseSteering = np.exp( 1j* phaseSteering )

    # locations is in wavelengths
    arrivalAnglesDeg = np.array([45]) 
    arrivalAnglesDeg = np.arange( 0 , 180 , 0.5 )
    
    
    # Loop over all angles of arrival 
    sums = []
    for aoa in arrivalAnglesDeg:
        waveFrontDistances = np.cos(  np.radians(aoa) ) * locations # in wavelengths 
        waveFrontPhases =  ( waveFrontDistances / 1.0 ) * 2 * np.pi  # radians

        cpxPhasePhysics = np.exp( 1j*waveFrontPhases)

        summation = np.sum( cpxPhasePhysics * cpxPhaseSteering ) 
        pow = summation * np.conj( summation )
        sums.append(  pow )
    # 
    maxPow = [(len( LOCATIONS))**2 ] * len( arrivalAnglesDeg)
    plt.plot( arrivalAnglesDeg , maxPow ,'r')
    plt.plot( arrivalAnglesDeg , sums)
    plt.show() 

def solve_1d( ):
    # Create the signals 
    Fs = 10.0e9
    freq = 100e6
    Nsamps = 100
    t = (1/Fs) * np.arange( 0 , Nsamps)
    F1 = Fs/10
    F2 = Fs/20
    sig1 = 10.0 * np.exp( 1j*(2*np.pi*t*F1))
    sig2 = 5.0 * np.exp( 1j*(2*np.pi*t*F2))


    array = phased.LinearArray( LOCATIONS , N=Nsamps , M=2 , noiseVar =1.0 )    
    array.add_signal( sig1 ,  40.0 , 0 )
    array.add_signal( sig2 ,  120.0 , 1 )
    

    signal = array.getOutput( )

    #aoa,power = simple_1d( elementLocations , signal , rf )
    aoa,power,eigs = mvdr_1d_spectrum( LOCATIONS, signal )
    # Plot all results 

    # Pull in the signal files
    plt.figure(2)
    plt.plot(  signal.transpose())

    plt.figure(3)
    plt.stem( np.real( eigs ) ) 


    plt.figure(1)
    plt.plot( aoa ,  power  )



    plt.show()


if __name__ == "__main__":
    #beam_pattern_1d(LOCATIONS,135)
    #beam_pattern_2d( LOCATIONS_2D ,180,45)
    solve_1d()
    #solve_2d() 
