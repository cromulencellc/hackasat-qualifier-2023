import ctf.challenge
import ctf.io
import ctf.timeout
import numpy as np
import spacestation
import time
class WrongAnswer(Exception):
    pass

def singleChal( station , tolerance ):
    station.print()
    cgGuess = ctf.io.input_number_array("What is the center of gravity? ", 3)
    cgCorrect = station.getCG()
    dCG = cgGuess - cgCorrect
    dCGMag = np.linalg.norm( dCG )    
    if dCGMag < tolerance:
        return True 
    else:
        raise WrongAnswer
    return False
@ctf.timeout.timeout( 120 )
def challenge( ):
    cgTolerance = 0.001
    c = ctf.challenge.Challenge()
    ctf.io.outputStr("Alright everyone, lets find our centers!")
    ctf.io.outputStr("The space station has a series of modules connected by tubes")
    ctf.io.outputStr("You can model each module as a point mass and the tubes as rigid and massless")
    ctf.io.outputStr("Each module has a gps receiver. You'll get the readings for the location of each module")
    ctf.io.outputStr("You give me the center of gravity of the space station")
    stations = spacestation.loadStations(cgTolerance)
    k=1
    correctCount = 0
    for station in stations:
        
        ctf.io.outputStr(f"Space station {k}")
        ok = singleChal( station , cgTolerance)
        if True == ok:
            ctf.io.outputStr("Correct!")
            correctCount += 1
        k += 1
    if correctCount == len(stations):
        ctf.io.outputStr("Yay!")
        ctf.io.outputStr( c.getFlag() )
    else:
        ctf.io.outputStr("Challenge error 2: contact admin")




if __name__ == "__main__":
    try:
        challenge()
    except spacestation.SpaceException:
        ctf.io.outputStr("Challenge error 1: contact admin")
    except ctf.timeout.TimeoutError:
        ctf.io.outputStr("Timeout")
    except WrongAnswer:
        ctf.io.outputStr("Wrong")
    ctf.io.outputStr("Bye")
    time.sleep( 10 )