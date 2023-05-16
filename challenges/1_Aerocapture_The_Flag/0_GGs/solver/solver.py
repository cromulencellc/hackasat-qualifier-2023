from pwn import *
import argparse as ap
import numpy as np

context.log_level = 'debug'

def solve_single(  inertia  ):

    # calculate inertia eighen values and eignevectors
    # 
    val,vec = np.linalg.eig( inertia)
    
    moiMin = np.argmin( val )
    minVec = vec[ : ,moiMin ] # get the column
    minMoiAxis = np.array2string( minVec , separator=",")
    minMoiAxis = minMoiAxis.replace("[","")
    minMoiAxis = minMoiAxis.replace("]","")

    return minMoiAxis
def solve( host , port ):
    r = remote( host , port )
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline( ticket )
    keep_going = True

    # 
    while( True == keep_going ):
        o = r.recvuntil( [b"intertia matrix for this satellite is", b"Bye."])
        if( o.endswith(b"Bye.")):
            print(o)

            keep_going = False
        else:
            print(o)
            itext = r.recvuntil( b"kg-m^2", drop=True)
            itext = itext.replace(b"[",b"")
            itext = itext.replace(b"]",b"")
            itext = itext.replace(b"\n",b"")
            I = np.fromstring(itext.strip(b" []"), sep=" ")
            I.shape = (3,3)
            answer = solve_single( I ) 
            r.sendline( answer )
            pass




if __name__ == "__main__":
    a = ap.ArgumentParser()
    a.add_argument("--hostname", required=True)
    a.add_argument("--port", required=True)
    args = a.parse_args()
    solve( args.hostname , args.port )
    #solve( "localhost","12345")