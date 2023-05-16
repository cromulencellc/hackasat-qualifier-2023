from pwn import *
import argparse
import momentum
import numpy as np

context.log_level = 'debug'

def run(r: remote):
    keepgoing = True 
    
    algo = momentum.Despin( 0 )
    k=0
    while keepgoing:
        out = r.recvuntil(b"magZ(T)\n" )
        strIn = r.recvline().decode().replace("\n","")
        arrayData = strIn.split(",")
        t = float( arrayData[0] ) 
        
        m = np.array( arrayData[7:10]).astype( np.float64 )
        w = np.array( arrayData[1:4]).astype( np.float64 )
        wheel = np.array( arrayData[4:7]).astype( np.float64 )
        r.recvuntil(b'Enter actuator command:')


        
        algo.setM( m )
        algo.setW( w )
        algo.setWheel( wheel )
        # calculate stuff
        algo.calculate()
        wheel = algo.getWheel()
        mtb = algo.getMtb()
        algo.printState(k)
        k=k+1
        out = np.concatenate( (wheel,mtb)).astype( str )
        cmdStr = ",".join( out )
        r.sendline( cmdStr.encode() )
        if np.abs( 3600 - t ) < 0.5:
            out = r.recvuntil(b"Bye").decode()
            print( out , flush=True ) 
            keepgoing = False



if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--hostname", required=True)
    a.add_argument("--port",required=True)
    args = a.parse_args()

    r = remote( args.hostname , args.port )

    # get ticket from environment
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline(bytes(ticket, 'utf-8'))

    run(r)