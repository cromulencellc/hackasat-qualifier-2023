import numpy as np

class PID:
    def __init__( self , Kp ,Ki,Kd):
        self.Kp = Kp
        self.Ki = Ki
        self.Kd = Kd 
        self.integral = 0.0
        self.last = 0.0
    def reset( self ):
        self.integral = 0.0
        self.last = 0.0
    def update( self,  error ):
        self.integral += error
        deriv = error - self.last
        out = self.Kp*error + self.Ki*self.integral + self.Kd*deriv
        self.last = error
        return out
class Despin:
    def __init__( self , intertia ):
        print("Angular Velocity (rad/s), Wheel Angular Velocity (rad/s), Wheel Torque Cmd (N-M), Dipole (T)",flush=True)
        self.intertia = np.array( [ 200, 0, 0, 0, 200, 0, 0, 0, 200 ]  ).reshape( 3,3 )
        self.KMag = 100000.0
        self.DCMbars = np.array([1,0,0,0,1,0,0,0,1]).reshape(3,3)
        self.wControl = PID( 0.05 , 0.0005 , 0.03 )
        

    def calculate( self ):
        
        # Calcualte a dipole command
        uSquared = np.power( np.linalg.norm( self.m )  , 2 ) 
        outOfPlane = np.matmul( self.magFieldMap , self.wheel )
        magTorqueBody = self.KMag * np.matmul( self.magFieldMap , outOfPlane )
        dipoleRequest = (1.0 / uSquared ) * np.matmul( self.magFieldMap , magTorqueBody )
        self.magT = magTorqueBody
        # Calculate a wheel torque command
        dw = self.wControl.update( self.w )
        self.torque = np.matmul( self.intertia, dw) +  np.cross(  self.H , self.w )
        self.dipole = dipoleRequest


    def getWheel(self):
        return self.torque
    def getMtb( self ):
        return self.dipole
    def setW( self, w ):
        self.w = w
        self.H = np.matmul( self.intertia , self.w )

    def setM( self, m ):
        self.m = m 
        ux = m[0]
        uy = m[1]
        uz = m[2]
        
        self.magFieldMap = np.array( [ 0.0, -uz, uy,
                             uz, 0.0, -ux,
                             -uy,ux,0.0
                           ] ).reshape( (3,3 ) )
                        
    def setWheel( self, wheel ):
        self.wheel = wheel
    def printState( self , prefix ):
        wMag=  np.linalg.norm( self.w )
        wheelMag = np.linalg.norm( self.wheel )
        print(f"{prefix}: {wMag}, {wheelMag}",flush=True)