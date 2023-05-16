import sys
from unittest import TestCase
from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
import scipy.constants
sys.path.append('phased_array')

import phased
import assertions
import numpy as np

import ut_tx

import time 



X_RANGE = [-.25,.25]
Y_RANGE = [-.25,.25]


class UT_2D( TestCase ):
    def setUp(self):
        LOCATIONS_2D = [ ( -0.25 , -0.25 ),
                         (  0.25  , -0.25 ),
                         (  0.25 , 0.25 ),
                         ( -0.25 , 0.25 ) ]


        Fs = 100000
        N = 10000
        Fc = 1000
        t = (1/Fs) * np.arange( 0,N)
        self.signal = (1/Fs)* np.exp( 1j*np.pi*2*t*Fc)
        
        self.array = phased.Array2D( LOCATIONS_2D , N=N , M=1 , noiseVar = 0.0 )    
    def test_0el_0az( self ):

        self.array.add_signal( self.signal , 0 , 0 , 0) 
        


        phases = self.array.getPhases()

        
        assertions.ASSERT_NEAR( phases[0][0] , phases[0][1],  "0==1")
        assertions.ASSERT_NEAR( phases[0][2] , phases[0][3],  "2==3")
        assertions.ASSERT_NEAR( phases[0][3]-phases[0][0] ,  np.pi,  " (3-0) = pi ")
        assertions.ASSERT_NEAR( phases[0][3] ,  np.pi/2,  "Location 3")
    def test_90az_0el( self ):
        
        self.array.add_signal( self.signal , 90 , 0 , 0) 
        
        phases = self.array.getPhases()

        
        assertions.ASSERT_NEAR( phases[0][2] , phases[0][1],  "2==1")
        assertions.ASSERT_NEAR( phases[0][3] , phases[0][0],  "3==0")
        assertions.ASSERT_NEAR( phases[0][1]-phases[0][0] ,  np.pi,  " (1-0) = pi ")
        assertions.ASSERT_NEAR( phases[0][1] ,  np.pi/2,  "Location 1")

    def test_180az_0el( self ):
        
        self.array.add_signal( self.signal , 180 , 0 , 0) 
      

        phases = self.array.getPhases()

        
        assertions.ASSERT_NEAR( phases[0][3] , phases[0][2],  "3==2")
        assertions.ASSERT_NEAR( phases[0][0] , phases[0][1],  "0==1")
        assertions.ASSERT_NEAR( phases[0][0]-phases[0][3] ,  np.pi,  " (0-3) = pi ")
        assertions.ASSERT_NEAR( phases[0][0] ,  np.pi/2,  "Location 0")

    def test_0az_90el( self ):
        
        self.array.add_signal( self.signal , 0 , 90 , 0) 
        
        phases = self.array.getPhases()

        # All phases equal
        assertions.ASSERT_NEAR( phases[0][3] , phases[0][2],  "3==2")
        assertions.ASSERT_NEAR( phases[0][0] , phases[0][1],  "0==1")
        assertions.ASSERT_NEAR( phases[0][3] , phases[0][1],  "3==1")
        # One of those equal phases is 0
        assertions.ASSERT_NEAR( phases[0][0] ,  0.0 , "phase = 0 " )
    def test_m45az_0el( self ):
                
        self.array.add_signal( self.signal , -45 , 0 , 0) 
        

        phases = self.array.getPhases()

        # All phases equal
        assertions.ASSERT_NEAR( phases[0][0] , phases[0][2],  "0==2") # same wavefront
        assertions.ASSERT_NEAR( phases[0][3] , -phases[0][1],  "3==(-1)") #symmetry
        assertions.ASSERT_NEAR( phases[0][0] ,  0 , "phase0 = 0 " ) # It aligns with the phase center
        # 3 can be calculated?
        d = np.sqrt( 2 * (1/4)**2 ) # wavelengths
        assertions.ASSERT_NEAR( phases[0][3] ,  2*np.pi*d , "phase = 0 " )
    def test_m45az_30el( self ):
        
        self.array.add_signal( self.signal , -45 , 30 , 0) 


        phases = self.array.getPhases()

        # All phases equal
        assertions.ASSERT_NEAR( phases[0][0] , phases[0][2],  "0==2") # same wavefront
        assertions.ASSERT_NEAR( phases[0][3] , -phases[0][1],  "3==(-1)") #symmetry
        assertions.ASSERT_NEAR( phases[0][0] ,  0 , "phase0 = 0 " ) # It aligns with the phase center
        # 3 can be calculated?
        d = np.cos( np.radians( 30 )  )*np.sqrt( 2 * (1/4)**2 ) # wavelengths
        assertions.ASSERT_NEAR( phases[0][3] ,  2*np.pi*d , "phase = 0 " )
    def test_45az_30el( self ):

        self.array.add_signal( self.signal , 45 , 30, 0) 
        phases = self.array.getPhases()

        # All phases equal
        assertions.ASSERT_NEAR( phases[0][3] , phases[0][1],  "3==1") # same wavefront
        assertions.ASSERT_NEAR( phases[0][2] , -phases[0][0],  "2==(-0)") #symmetry
        assertions.ASSERT_NEAR( phases[0][1] ,  0 , "phase0 = 0 " ) # It aligns with the phase center
        # 3 can be calculated?
        d = np.cos( np.radians( 30 )  )*np.sqrt( 2 * (1/4)**2 ) # wavelengths
        assertions.ASSERT_NEAR( phases[0][2] ,  2*np.pi*d , "phase = 0 " )
    def test_135az_30el( self ):
        self.array.add_signal( self.signal , 135 , 30 , 0) 
        
        phases = self.array.getPhases()

        # All phases equal
        assertions.ASSERT_NEAR( phases[0][2] , phases[0][0],  "2==0") # same wavefront
        assertions.ASSERT_NEAR( phases[0][3] , -phases[0][1],  "3==(-1)") #symmetry
        assertions.ASSERT_NEAR( phases[0][2] ,  0 , "phase0 = 0 " ) # It aligns with the phase center
        # 3 can be calculated?
        d = np.cos( np.radians( 30 )  )*np.sqrt( 2 * (1/4)**2 ) # wavelengths
        assertions.ASSERT_NEAR( phases[0][1] ,  2*np.pi*d , "phase = 0 " )
if __name__ == "__main__":
    t = UT_2D()
    t.setUp()
    t.test_90az_0el()