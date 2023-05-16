import numpy as np
import matplotlib.pyplot as plt
class BatchFilter:
    def __init__(self,  num_states , num_measures):
        self.N = num_states
        self.M = num_measures
        pass
    def init( self, x):
        self.x0 = x
        self.ys = []
        self.ts = []
    def measurment_fcn( self, fcn ):
        self.measurement = fcn
    def jacobian_fcn( self,  fcn ):
        self.jacobian = fcn
    def add_measurement(self, t, y  ):

        yCol = np.array( y )
        yCol.shape = (self.M ,1 )
        self.ys.append(yCol)
        self.ts.append( t )
    def estimate( self , iterations ):
        stateCorrections  = np.zeros( (self.N , iterations))
        x = np.array( self.x0 ) 
        x.shape = ( self.N , 1 )
        for i in range( iterations ):
            
            LAM = np.zeros((self.N,self.N))
            N = np.zeros((self.N,1))
            # loop over the measurements
            for t,y in zip(self.ts, self.ys ):
                H = self.jacobian( t,  x )
                HT = np.transpose( H )
                y_est = self.measurement( t,  x )
                dy = y - y_est
                N = N + ( HT @ dy )
                LAM = LAM + (HT @ H )
            x_hat = np.linalg.inv( LAM ) @ N 
            stateCorrections[:,[i]] = x_hat
            x = x + x_hat
            

        plt.figure()
        plt.plot( np.transpose(stateCorrections ) ) 
        leg = [ f"x_{i}" for i in range(self.N) ]
        plt.gca().legend(leg)

        plt.show()
        return x
