import numpy as np
import matplotlib.pyplot as plot


class FilterPython:
    def __init__(self):
        posVar = 100
        accelVar = 0.01
        self.C = np.zeros((3,6))
        self.C[0:3, 0:3] = np.identity(3)        
        self.A = np.zeros((6,6))
        self.A[0:3,3:6 ] = np.identity(3)
        self.G = np.zeros((6,3 ))
        self.G[3:6,0:3] = np.identity(3)
        self.R = np.matrix( [100, 10, 10, 10, 100, 10, 10, 10, 100] )
        self.R.shape = (3,3)
        self.Q = np.identity(3) * accelVar 

        pass
    def init( self , pos , vel ):
        self.x = np.concatenate( (pos,vel)).reshape(6,1)
        self.P = np.identity(6) * 1
        
    def run( self, accels, positions ):
        k = 0 
        lastTime = 0 
        self.T = []
        self.X = []
        self.Y = []
        self.Z = []
        self.C1 = []
        self.C2 = []
        self.C3 = []
        nextPos = positions[0]

        for accel in accels:
            t = accel["time"]
            a = accel["accel"]
            pT = nextPos["time"]
            self.T.append( t ) 

            if ( t > pT ):
                print("Correcting")
                p = nextPos["pos"]
                dt1 =  pT - lastTime 
                dt2 = t - pT
                self.Propegate( a , dt1 )
                self.correction( p )
                self.Propegate( a, dt2 )
                try:
                    k=k+1
                    nextPos = positions[k]
                except:
                    nextPos = {"time":100000000000000000000000000000 }
                    pass
                
            else:
                
                dt = t - lastTime

                self.Propegate( a , dt )
                pass
            print( f"{t},{self.x[0]},{self.x[1]},{self.x[2]}")
            lastTime = t
            self.X.append( self.x[0])
            self.Y.append( self.x[1])
            self.Z.append( self.x[2])
            self.C1.append( self.P[0,0]  )
            self.C2.append( self.P[1,1]  )
            self.C3.append( self.P[2,2]  )
        plot.plot( self.T , self.C1 , color="b" )
        plot.plot( self.T , self.C2, color="r")
        plot.plot( self.T , self.C3 , color="k")
        plot.show()

    def Propegate( self , accel, dt):
        vel = self.x[3:6]
        pos = self.x[0:3]
        pos = pos + ( vel*dt) + ( 0.5 * accel * dt * dt )
        vel = vel + ( accel * dt )
        self.x = np.concatenate( (pos,vel ))
        STM = np.identity(6) + self.A*dt
        self.P =  (STM @ ( self.P @ np.transpose(STM) ))  + ( self.G @ ( self.Q @ np.transpose( self.G )))
        pass
    def correction( self , pos):
        y = pos
        yExpected = self.x[0:3]
        dy = y - yExpected
        S = self.C @( self.P @ np.transpose( self.C )) + self.R
        K = self.P @ ( np.transpose( self.C )  @ np.linalg.inv( S ) ) 
        self.P = self.P - ( K @ ( self.C  @ self.P ) ) 
        dx = K @ dy   
        

        self.x = self.x + dx 
    def getEstimate( self ):
        return self.x[0:3]
    def getConfidence( self ):
        posCov = self.P[ 0:3 , 0:3] # Get PxP terms of cov
        e = np.linalg.eig( posCov )[0]
        return e