import ctf.challenge as C
import ctf.io as IO
import ctf.timeout as TO
import shared
import numpy as np
#import filter
import filter_binary

def boundsCheck( value , min, max ):
    if not np.isfinite( value ):
        return False 
    return ( value <= max ) and (value >= min)
class FlagPlease(Exception):
    pass
class Incorrect(Exception):
    pass


def run():
    maxRange = 10
    maxCov = 10

    # Run filter
    
    #kf = filter.FilterPython( )
    #kf.init( np.array([0,0,0]),  np.array([0,0,0]))
    #kf.run( accels=accels, positions=positions)
    kf = filter_binary.FilterBinary()
    kf.run()
    pos = kf.getLastPosition()
    posCov = kf.getCovariance()
    posCovEig = np.linalg.eig( posCov )[0]
    N = kf.getNumEstimates() 

    range = np.linalg.norm( pos)
    positionOk = boundsCheck( range , 0, maxRange )
    covOkCount = 0 
    for c in posCovEig:
        covOk = boundsCheck( c , 0 , maxCov )
        if True == covOk:
            covOkCount += 1
    if N != len( shared.times ):
        print("Wrong number of estimates received")
        raise Incorrect
    if True == positionOk:
        if covOkCount == 3:
            raise FlagPlease("give me flag")
        else:
            IO.outputStr("You reached the docking station but your kalman filter isnt confident in your position")
            IO.outputStr(f"I want the principal axes of my position error covariance matrix to be less than {maxCov} m^2")
    else:
        IO.outputStr(f"I want to be within {maxRange} m of the docking station before I give out the flag.")

@TO.timeout( 120 )
def challenge():
    
    f =  C.Challenge( )
    try: 


        run()
    
    except FlagPlease:
        flag = f.getFlag()
        IO.outputStr("The kalman filter says we are at the docking station. We must be there!")
        IO.outputStr("Here is the flag: ")
        IO.outputStr( flag )
        pass
    except TO.TimeoutError:
        IO.outputStr("Timeout..")
    except Incorrect:
       pass
    except:
        IO.outputStr("Woah you crashed the challenge.")
    IO.outputStr("Bye.")

if __name__ == "__main__":
    challenge()