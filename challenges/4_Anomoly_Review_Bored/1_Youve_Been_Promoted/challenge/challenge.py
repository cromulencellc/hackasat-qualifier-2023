from ctf import challenge
from ctf import io
from ctf import timeout
import sim 
@timeout.timeout(seconds=1000)
def run( ):
    c = challenge.Challenge( )
    runTime = 3600
    wheelLimit = 20
    wLimit = 0.001
    io.outputStr("Send me commands to get the spacecraft under control and the spacecraft despun")
    io.outputStr(f"You must run for {runTime} seconds")
    io.outputStr(f"Make sure the magnitude of the spacecraft angular velocity vector is less than {wLimit} (rad/s)")
    io.outputStr(f"Make sure each reaction wheel has a spin rate that is between -{wheelLimit} and {wheelLimit} (rad/s)")
    io.outputStr("")
    try: 
        runTime 
        s = sim.Simulator()
        s.run(runTime)

        success = s.grade( wLimit=wLimit , wheelLimit=wheelLimit )
        if True == success:
            io.outputStr("Momentum managed....maybe you can get promoted to battery management?")
            io.outputStr("Here is your flag:")
            io.outputStr( c.getFlag() )
        else:
            io.outputStr("You need to work on your management skills")
    except timeout.TimeoutError:
        io.outputStr("Timeout....")
    except:
        io.outputStr("Woah that didnt work")
    io.outputStr("Bye")
    
if __name__ == "__main__":
    run() 