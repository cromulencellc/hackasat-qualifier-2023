
from pwn import *
import argparse
import time

context.log_level = 'debug'

def solve( host , port , maneuver_file ):
    r = remote( host=host, port=port )
    
    keepgoing = True 
    
    # get ticket from environment
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline( ticket )

    
    f = open(maneuver_file , "rt")
    maneuvers = f.readlines()
    # loop over all maneuvers
    for dv in maneuvers:
        cmd = dv.strip("\n")
        r.recvuntil(b"Input next maneuver:")
        print(f"Sending maneuver: {cmd}")
        r.sendline(cmd.encode("utf-8")  )

    out = r.recvuntil( b"Quitting")
    print( out.decode() )
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Description of your program')
    parser.add_argument('--maneuvers', help='Run the solver but skip relativity', default="solution.txt")
    parser.add_argument('--host', help='Challenge remote host')
    parser.add_argument('--port', help='Challenge remote port')
    args = parser.parse_args()
    

    solve( args.host, args.port , args.maneuvers)
    time.sleep( 100 )
    sys.exit(0)
