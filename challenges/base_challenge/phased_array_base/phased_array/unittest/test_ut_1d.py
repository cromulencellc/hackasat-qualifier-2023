import sys
from unittest import TestCase

sys.path.append('phased_array')

import phased
import assertions
import numpy as np

import numpy as np

        

class UT_1D( TestCase ):
    def setUp(self):

        Fs = 100000
        location =  np.array( [-1,-0.5, 0 ,0.5, 1] ) 
        N = 10000
        Fc = 1000
        t = (1/Fs) * np.arange( 0,N)
        self.signal = (1/Fs)* np.exp( 1j*np.pi*2*t*Fc)
        
        self.array = phased.LinearArray( location , N=N , M=1 , noiseVar = 0.0 )    

    def test_0el( self ):
        
        self.array.add_signal(self.signal, 0 ,0 )


        phases = self.array.getPhases()[0]

        
        assertions.ASSERT_NEAR( phases[0] , -2*np.pi,  "Location 0")
        assertions.ASSERT_NEAR( phases[1] , -1*np.pi,  "Location 1")
        assertions.ASSERT_NEAR( phases[2] ,  0*np.pi,  "Location 2")
        assertions.ASSERT_NEAR( phases[3] ,  1*np.pi,  "Location 3")
        assertions.ASSERT_NEAR( phases[4] ,  2*np.pi,  "Location 4")
    def test_180el( self ):
        
        self.array.add_signal(self.signal ,180, 0  )



        phases = self.array.getPhases()[0]

        
        assertions.ASSERT_NEAR( phases[0] ,  2*np.pi,  "Location 0")
        assertions.ASSERT_NEAR( phases[1] ,  1*np.pi,  "Location 1")
        assertions.ASSERT_NEAR( phases[2] ,  0*np.pi,  "Location 2")
        assertions.ASSERT_NEAR( phases[3] , -1*np.pi,  "Location 3")
        assertions.ASSERT_NEAR( phases[4] , -2*np.pi,  "Location 4")

    def test_90el(self):
        self.array.add_signal( self.signal , 90 ,0 )


        phases = self.array.getPhases()[0]

        
        assertions.ASSERT_NEAR( phases[0] ,  0*np.pi,  "Location 0")
        assertions.ASSERT_NEAR( phases[1] ,  0*np.pi,  "Location 1")
        assertions.ASSERT_NEAR( phases[2] ,  0*np.pi,  "Location 2")
        assertions.ASSERT_NEAR( phases[3] ,  0*np.pi,  "Location 3")
        assertions.ASSERT_NEAR( phases[4] ,  0*np.pi,  "Location 4")
        pass

    def test_30el(self):
        self.array.add_signal( self.signal, 30 , 0 )


        phases = self.array.getPhases()[0]

        a = 30 * np.pi / 180.0
        assertions.ASSERT_NEAR( phases[0] ,  -2*np.cos(a)*np.pi,  "Location 0")
        assertions.ASSERT_NEAR( phases[1] ,  -1*np.cos(a)*np.pi,  "Location 1")
        assertions.ASSERT_NEAR( phases[2] ,   0*np.pi,            "Location 2")
        assertions.ASSERT_NEAR( phases[3] ,   1*np.cos(a)*np.pi,  "Location 3")
        assertions.ASSERT_NEAR( phases[4] ,   2*np.cos(a)*np.pi,  "Location 4")
        pass
    def test_150el(self):
        self.array.add_signal( self.signal, 150 , 0)



        phases = self.array.getPhases()[0]

        a = 30 * np.pi / 180.0
        assertions.ASSERT_NEAR( phases[0] ,   2*np.cos(a)*np.pi,  "Location 0")
        assertions.ASSERT_NEAR( phases[1] ,   1*np.cos(a)*np.pi,  "Location 1")
        assertions.ASSERT_NEAR( phases[2] ,   0*np.pi,            "Location 2")
        assertions.ASSERT_NEAR( phases[3] ,  -1*np.cos(a)*np.pi,  "Location 3")
        assertions.ASSERT_NEAR( phases[4] ,  -2*np.cos(a)*np.pi,  "Location 4")
        pass
if __name__ == "__main__":
    t = UT_1D()
    t.setUp()
    t.test_0el()