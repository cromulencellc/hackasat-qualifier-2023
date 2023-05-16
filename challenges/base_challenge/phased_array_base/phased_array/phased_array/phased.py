from scipy.spatial.transform import Rotation as R

import numpy.random
import numpy as np

def columnRotHelper( axis , angle ):
    return np.squeeze(R.from_euler( axis, [angle],degrees=True).as_matrix()).transpose()

class LinearArray():
    # elementLocations: array element locations units of wavelength
    # N: Number of samples
    # M: Number of signals
    def __init__( self , elementLocations , N , M,  noiseVar=1.0, dtype=np.complex64):
        self.L = len( elementLocations )
        self.N = N 
        self.M = M 
        self.X = np.zeros( (self.L,self.N, self.M ) , dtype=dtype)
        noiseDev = np.sqrt( noiseVar )*np.sqrt(2)/2
        realNoise = np.random.normal(loc=0.0, scale=noiseDev , size=(self.L, self.N))
        imagNoise = np.random.normal(loc=0.0, scale=noiseDev , size=(self.L, self.N))
        noise = realNoise + 1j*imagNoise
        self.noise = noise.astype('complex64')
        self.location = elementLocations
        self.phases = np.zeros( (M,self.L))
    def getNumElements( self ):
        return self.L
    # signal: np.array of complex 64 samples
    # angleDegrees: angle of arrival in degrees - 0 is parallel to the array
    # k signal number 
    def add_signal( self , signal , angleDegrees,  k ):
        waveDelay = np.cos( np.radians( angleDegrees)  ) * self.location
        phase = np.pi * 2 * waveDelay
        cpxPhase = np.exp( 1j * phase )
        self.phases[k,:] = phase
        signalRcv = np.outer( cpxPhase , signal ) 
        self.X[ : , : , k] = signalRcv
    def getPhases( self ):
        return self.phases
    def getOutput( self ):
        signal = np.sum( self.X , axis=2) + self.noise
        return signal 




class Array2D():
    def __init__( self , elementLocations , N , M,  noiseVar=1.0, dtype=np.complex64):
        self.locations =  elementLocations
        
        
        self.L = len(elementLocations)
        self.N = N 
        self.M = M 
        noiseDev = np.sqrt( noiseVar )*np.sqrt(2)/2
        realNoise = np.random.normal(loc=0.0, scale=noiseDev , size=(self.L, self.N))
        imagNoise = np.random.normal(loc=0.0, scale=noiseDev , size=(self.L, self.N))
        
        noise = realNoise + 1j*imagNoise
        self.noise = noise.astype('complex64')
        self.location = elementLocations
        self.phases = np.zeros( (M,self.L))
        self.X = np.zeros( (self.L,self.N, self.M ) , dtype=dtype)

    def printAntennaFile( self , filename , rfFreq ):
        antennaTxt = "ID,East (m),North (m)\n"
        antennaTxt += "-----------------------\n"
        counter = 0 
        for loc in self.locations:
            antennaTxt += f"{counter},{loc[0]},{loc[1]}\n"
        f = open(filename,"wt")
        f.write( antennaTxt )
        f.close()
    def add_signal( self, signal , azimuthDegrees , elevationDegrees , k ):
        # Calculate the phase delay at each element
        azRot = columnRotHelper("x", -azimuthDegrees )
        elRot = columnRotHelper("y",-(90.0-elevationDegrees))
        UEN_2_LOS = np.matmul( elRot,  azRot )
        LOS_2_UEN  = UEN_2_LOS.transpose()
        los_LOS_Frame = np.array( [1,0,0] )
        los_UEN_FRAME = np.matmul( LOS_2_UEN , los_LOS_Frame )
        phases = []
        for location in self.locations:
            loc_UEN = np.array( [ 0 , location[0], location[1]])
            waveDelay = np.dot( loc_UEN  , los_UEN_FRAME  ) # This is the projection of the location diference onto the line of sight 
            phase =  ( waveDelay  ) * 2* np.pi
            phases.append( phase )
        self.phases[k,:] = np.array( phases ) 
        cpxPhase = np.exp( 1j *  np.array( phases )  )
        signalRcv = np.outer( cpxPhase , signal ) 
        self.X[ : , : , k] = signalRcv
    def getPhases( self , ):

        return self.phases
    def getOutput( self ):
        signal = np.sum( self.X , axis=2) + self.noise
        return signal 
