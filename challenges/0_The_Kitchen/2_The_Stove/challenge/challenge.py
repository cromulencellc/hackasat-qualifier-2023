import sys
import ctf.challenge as Challenge
import ctf.io as IO
import ctf.timeout as TO


@TO.timeout(10) # CTF timeout decorator makes the function timeout
def main( ):
    f = Challenge.Challenge( ) # Use CTF package flag class to load the flag and cleanup the env
    expected = "flag please" 
    out = IO.input_str(f"Enter '{expected}' to get the flag: ") 
    
    if out == expected:
        # IO.ouputStr will do "flushing output"
        IO.outputStr("Here is your flag:") 
        IO.outputStr( f.getFlag() ) 
    else:
        IO.outputStr("Wrong")

if __name__ == "__main__":
    # Make sure to wrap main in a try/catch
    try:
        main( )
    except TO.TimeoutError:
        # print out some sort of error if things timeout
        IO.outputStr("\n\nTimeout --- bye\n\n")
 