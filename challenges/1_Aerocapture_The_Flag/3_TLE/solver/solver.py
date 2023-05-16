from pwn import *
import argparse
import tle_filter

context.log_level = 'debug'

def solve_single( r ):
    
    # Get catalog and epoch
    r.recvuntil(b"catalog #")
    catalog = int( r.recvuntil(b"epoch ", drop=True) ) 
    epoch   = r.recvuntil(b"UTC")
    r.recvuntil(b"This satellite is ", drop=True)

    c = r.recvuntil( b"\nThis satellite was part ",drop=True)
    if( b"Unclassified" in c):
        classification = "U"
    else:
        classification = "S"
    part = r.recvuntil(b" of the ", drop=True).decode()
    num  = int( r.recvuntil(b" launch of the year", drop=True) ) 
    yr   = int( r.recvuntil(b"\nHere are", drop=True) ) 
    # Goto start of position vectors
    r.recvuntil(b"--------------------------\n")
    # Get the positions
    dataString = r.recvuntil(b"\nWhat is TLE line 1:", drop=True)
    data = tle_filter.fromString( dataString )
    t = tle_filter.TleSolver( data )
    tle1,tle2= t.estimate(epoch.decode(),  catalog, classification ,yr, num ,part )
    ##
    r.sendline(tle1)
    r.recvuntil(b"What is TLE line 2:")
    r.sendline(tle2)
    
    
def solver( hostname , port ):
    r = remote( hostname , port )
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline( ticket )

    keep_going = True
    while( keep_going ):
        o = r.recvuntil([b"monitoring is", b"Bye"])
        print(o)
        if( o.endswith(b"Bye")):
            keep_going = False
        else:
            solve_single( r )

if __name__ ==  "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--port", required=True)
    args = ap.parse_args()
    solver( args.hostname ,args.port)
    #solver( "localhost", 12345 )