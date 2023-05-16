from pwn import *
import argparse as ap
import numpy as np

context.log_level = 'debug'

def calc_cg( modules ):
    mu = 398604.418
    sumForce = np.array([0.0,0.0,0.0])
    sumMass = 0.0
    for mod in modules:
        m = mod["mass"]
        p = mod["loc"]
        p3 = np.linalg.norm( p ) ** 3 
        F = - mu * m * p / p3 
        sumMass += m
        sumForce += F
    forceMag = np.linalg.norm( sumForce )
    unitDirection = sumForce / forceMag
    # Fg = Mu * m / r^2 
    gravDistance = np.sqrt( mu * sumMass / forceMag )
      
    cg = -unitDirection * gravDistance 
    return cg
def solve_single( r ):
    keep_going = True
    mods = [] 
    

    while( keep_going ):
        o = r.recvuntil([b"Module",b"mass",b"position [x,y,z]", b"gravity?"])
        if o.endswith(b"Module"):
            num = r.recvuntil(b":")
            d = {}
        elif o.endswith( b"mass"):
            mass = r.recvuntil(b"kg",drop=True)
            d["mass"] = float( mass ) 
        elif o.endswith(b"position [x,y,z]"):
            pos = r.recvuntil(b"km" , drop=True )
            posVec=  np.fromstring(pos.strip(b" []"), sep=" ")
            d["loc"] = np.array( posVec ) 
            mods.append( d )
        elif o.endswith(b"gravity?"):
            keep_going = False
        else:
            print("Error")
    cg = calc_cg( mods )
    return cg

def solve( host , port ):
    r = remote( host , port )
    ticket = os.getenv("TICKET")
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline( ticket )
    keep_going = True
    while( keep_going ):
        o = r.recvuntil([ b"Space station" , b"Bye"] )
        print(o.decode())
        if o.endswith(b"Bye"):
            keep_going = False
        else:
            cg = solve_single( r )
            answer = f"{cg[0]},{cg[1]},{cg[2]}"
            r.sendline( answer )
            
if __name__ == "__main__":
    a = ap.ArgumentParser()
    a.add_argument("--hostname", default="localhost")#required=True)
    a.add_argument("--port", default=12345)#required=True)
    args = a.parse_args()
    solve( args.hostname , args.port )