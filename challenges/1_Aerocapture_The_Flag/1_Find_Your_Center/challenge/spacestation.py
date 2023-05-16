import numpy as np
import ctf.io
mu = 398604.418
R = 6378 + 1000
C = np.array([R,0,0])
class SpaceException(Exception):
    pass


def loadStations( tolerance ):
    m1 = [ Module(5000 , [5,0,0]),
           Module(5000, [-5,0,0]),
    ]
    m2 = [
        Module( 1000 ,[0,5,0]),
        Module( 1000 ,[0,-5,0])
    ]
    m3 = [
        Module( 10000, [0,5,0]),
        Module( 10000, [0,-5,0])
    ]
    m4 = [
        Module( 10000 , [1,0,0]),
        Module( 2500 , [-5,0,0])
    ]
    m5 = [
        Module( 10000, [1,0,0]),
        Module( 2000, [0,-5,0]),
        Module( 1500, [-10,0,0])
    ]
    s1 = SpaceStation( m1 ,tolerance)
    s2 = SpaceStation( m2 , tolerance)
    s3 = SpaceStation( m3 , tolerance)
    s4 = SpaceStation( m4 , tolerance)
    s5 = SpaceStation( m5 , tolerance)
    o = [s1,s2,s3,s4,s5]
    return o
class Module:
    def __init__( self , mass, relLoc):
        self.mass = mass
        self.loc = C + relLoc
        pass
    

class SpaceStation:
    def __init__( self, modules, tol ):
        self.modules = modules 
        
        cg = self.getCG() 
        cm = self.getCM()

        delta = np.linalg.norm( cg - cm ) 
        if( delta < tol ):
            raise SpaceException
    def print( self ):
        k = 0
        for m in self.modules:
            ctf.io.outputStr(f"Module {k}: mass {m.mass} kg, position [x,y,z] {m.loc} km")
            k = k + 1
    def getCG( self ):
        sumForce = np.array([0.0,0.0,0.0])
        sumMass = 0.0
        for m in self.modules:
            r3 = np.linalg.norm( m.loc ) ** 3
            gVec = (-mu * m.mass * m.loc )  / r3
            sumMass += m.mass
            sumForce += gVec
        # Fmag = Mu * m /  r^2 
        # r = sqrt( Mu * m / Fmag)
        # F = ( Mu * m * loc ) / ( R^3)
        totalForce = np.linalg.norm( sumForce )
        gravDir = sumForce / totalForce
        gravDistance = np.sqrt(  ( mu * sumMass ) / totalForce )
        cg = -sumForce * np.power( gravDistance ,3 ) / ( mu * sumMass)
        return cg
    def getCM( self ):
        MM = np.array([0,0,0])
        M = 0
        for m in self.modules:
            M += m.mass
            MM += ( m.mass * m.loc )
        cm =  MM / M
        return cm
    