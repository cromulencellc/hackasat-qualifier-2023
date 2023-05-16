import ctf.challenge as Challenge
import ctf.io as IO
import ctf.timeout as TO

import starlist

class WrongAnswer( Exception ):
    pass


@TO.timeout(100) # CTF timeout decorator makes the function timeout
def main( ):
    f = Challenge.Challenge( ) # Use CTF package flag class to load the flag and cleanup the env
    timeStr = starlist.OBSERVATION_TIME.strftime("%Y-%m-%d %H:%M:%S UTC")
    IO.outputStr("Help us detect the Trisolaran fleet.")
    IO.outputStr("Identify the stars from which the fleet originates by their Hipparcos Star Catalog number. Then we will send our fleet out to intercept them!")
    IO.outputStr(f"The trisolaran empire is within {starlist.MAX_DISTANCE_LY} light years of Earth")
    IO.outputStr(f"The signals were received at: {timeStr}")
    IO.outputStr(f"The antenna array is centered at")
    IO.outputStr(f"Latitude: {starlist.OBSERVATORY_LLA[0]} deg")
    IO.outputStr(f"Longitude: {starlist.OBSERVATORY_LLA[1]} deg")
    IO.outputStr(f"Altitude: {starlist.OBSERVATORY_LLA[2]} m")
    IO.outputStr(f"The signals were recieved at: {starlist.RF_FREQ} HZ")
    nearest = IO.input_int(f"What is the nearest star from which fleet ships originate? ") 

    
    
    starsSorted = starlist.sortByDistance( starlist.STARS )
    N = len( starsSorted )
    if nearest == starsSorted[0]:
        IO.outputStr("Correct!")
    else:
        IO.outputStr("Wrong!")
        raise WrongAnswer
    
    IO.outputStr(f"What are the remaining {N-1} stars?")
    IO.outputStr(f"Enter as comma seperated list (ex: 1,2,3,4)")
    otherStars = IO.input_number_array("stars? ", N-1)

    if set(otherStars) == set( starsSorted[1:]):
        IO.outputStr("Correct!")
        flag = f.getFlag()
        IO.outputStr("Thanks for saving earth")
        IO.outputStr(f"Here is your flag {flag}")
    else:
        IO.outputStr("Wrong")
        raise WrongAnswer



if __name__ == "__main__":
    # Make sure to wrap main in a try/catch
    try:
        main( )
    except WrongAnswer:
        IO.outputStr("\n\nWe sent our ships in the wrong direction and they didn't intercept the Trisolaran fleet")
    except TO.TimeoutError:
        # print out some sort of error if things timeout
        IO.outputStr("\n\nTimeout")
    IO.outputStr("Bye..")
