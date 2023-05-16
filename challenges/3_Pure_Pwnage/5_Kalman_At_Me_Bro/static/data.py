import random
import numpy as np
import struct
from scipy.spatial.transform import Rotation as R
import shared
def sec_to_us( sec ):
    return int( np.floor( sec * 1000000 ))

def float_to_fixed( floatValue , fraction_bits=10 ):
    scalar = ( 2 ** fraction_bits ) 
    scaledValue = floatValue * scalar 
    intValue = int( scaledValue )
    return intValue

class Data:
    def __init__( self , times  ):
        self.t =times
        T = self.t[-1]
        self.tgo = T -self.t
        C = -0.1
        C1 = -0.02
        r = R.from_quat([0, 0, np.sin(np.pi/10), np.cos(np.pi/10)])
        self.DCM = r.as_matrix( )
        self.a = C*self.tgo + C1
        self.v = (C/2.0)*( self.tgo ** 2 ) + ( C1 * self.tgo )
        self.p = (C/6.0)*( self.tgo ** 3 ) + ( C1/2.0) * ( self.tgo ** 2 ) +30
        self.N = len( self.t )
    def getN( self ):
        return self.N
    def dumpAccel( self, fileName ):
        f = open( fileName, "wb")

        for accel in self.measuredAccels:
            t = sec_to_us( accel["time"] ) 
            a = accel["accel"].flatten()
            dataOut = [t , a[0],a[1],a[2]]
            outBytes = struct.pack("<Q3d", *dataOut)
            
            
            f.write( outBytes )
        f.close()
    def dumpPositions( self , filename ):
        f = open( filename, "wb")
        k=0
        for item in self.measuredPositions:
            t = sec_to_us( item["time"]  ) 
            a = item["pos"].flatten()
            iOut = [ float_to_fixed(x) for x in a ]
            dataOut = [t , iOut[0],iOut[1],iOut[2]]
            outBytes = struct.pack("<Q3q", *dataOut)
            f.write( outBytes )
            #print(k)
            k+=1
        f.close()
    def genAccel( self , accelVar ):
        sigma = np.sqrt( accelVar )

        out = []
        for t,a in zip( self.t , self.a ):
            d = {} 
            noise = np.random.normal( 0.0 , sigma , 3).reshape(3,1)

            aVector = np.array( [a,0,0]).reshape(3,1) + noise
            d["time"] = t
            d["accel"] = ( self.DCM @ aVector )  
            out.append( d )
        self.measuredAccels = out 
        return out 
    def genPos( self , posVar , decim ):
        sigma = np.sqrt( posVar )
        Pout = self.p[::decim]
        Tout = self.t[::decim]

        noise = np.random.normal( 0.0 , sigma , len( Pout ))
        out = []
        for t,p,n in zip( Tout,Pout,noise):
            d = {} 
            d["time"] = t
            posVector = np.array( [p,0,0] ).reshape( 3,1 )
            d["pos"] =  (self.DCM @  posVector ) + n 
            out.append( d )
        self.measuredPositions = out
        return out

if __name__ == "__main__":
    T=101
    d = Data( shared.times )
    accels = d.genAccel(0)
    positions = d.genPos( 0 , 100)
    # Dump data
    d.dumpAccel( "accels.bin")
    d.dumpPositions( "positions.bin")
    print("Generated")