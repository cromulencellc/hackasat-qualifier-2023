from pwn import *

# contact solver
import os
import sys
import struct

import numpy as np
from skyfield.api import load, wgs84, EarthSatellite
from skyfield.toposlib import GeographicPosition

context.log_level = 'debug'

ts = load.timescale()

class GroundStation:
    def __init__(self, name, pos: GeographicPosition):
        self.name = name
        self.pos = pos

groundStations = [
    GroundStation('Cape Canaveral', wgs84.latlon(28.40, -80.61, 27)),
    GroundStation('Cape Cod',       wgs84.latlon(41.70, -70.03, 9)),
    GroundStation('Anchorage',      wgs84.latlon(61.21, -149.90, 40)),
    GroundStation('Vandenberg',     wgs84.latlon(34.76, -120.52, 122)),
    GroundStation('Denver',         wgs84.latlon(39.74, -104.98, 1594))
]

def simulate(params):
    [inc,raan,ecc,aop,ma,mm] = params
    tle = f"""
HACKASAT
1 75001F 23750A   23091.00000000  .00000000  00000-0  00000-0 0     1
2 75001 {inc:8.4f} {raan:8.4f} {ecc:0>7.0f} {aop:8.4f} {ma:8.4f} {mm:17.14f}
"""
    lines = tle.strip().splitlines()
    sat = EarthSatellite(lines[1], lines[2], lines[0], ts)

    t = sat.epoch
    dur = 8/24 # 8 hours
    dt = 1/24/60 # dt = 1 minute

    n = dur / dt

    contactTime = 0
    contact = False

    i = 0
    while (i <= n):
        # Check ground station contacts
        satPos = sat.at(t).position.km
        if np.linalg.norm(satPos) <= 6378.14+300:
            print("The satellite burned up in the atmosphere!! Keep it above 300km.")
            return 0
        contact = False
        for gnd in groundStations:
            gndPos = gnd.pos.at(t).position.km
            r = satPos - gndPos
            rMag = np.linalg.norm(r)
            if rMag <= 6000:
                v1_u = gndPos / np.linalg.norm(gndPos)
                v2_u = r / rMag
                A = 90 - np.arccos(np.clip(np.dot(v1_u, v2_u), -1.0, 1.0)) * 180/np.pi
                if A >= 15:
                    contact = True

        if contact:
            contactTime += 1 # 1 minute
        
        # Propagate satellite orbit
        t += dt
        i += 1

    return contactTime

def localOpt(guess, param, delta):
    localOptContactTime = 0
    p0 = guess[param]
    best = guess
    for d in delta:
        guess[param] = p0 + d # jiggle the state to see if we get a better result
        contactTime = simulate(guess)
        print(f"{guess}, Contact time: {contactTime}")
        if contactTime >= localOptContactTime:
            pb = guess[param]
            localOptContactTime = contactTime
    
    best[param] = pb
    print(f"Local Optimum: {best}, Contact time: {localOptContactTime}")
    return [best, localOptContactTime]

def solve():
    # Initial guess for orbital parameters
    inc  = 45 # ground stations located in northen hemisphere
    raan = 0
    ecc  = 2000000 # eccentricy to dwell over a specific region
    aop  = 0
    ma   = 0
    mm   = 10 # 10revs/day ~2500 km altitude for a circular orbit, want a higher orbit for longer dwell but not too high because 6000 km range limit

    i=0
    contactTime = 0
    prevContactTime = 0
    bestContactTime = 0
    best = [inc,raan,ecc,aop,ma,mm]
    
    [best, bestContactTime] = localOpt(best,1,range(0,360,10)) # jiggle raan first to approx align orbit over ground stations
    [best, bestContactTime] = localOpt(best,3,range(0,360,10)) # jiggle aop to align apogee over grounds stations
    [best, bestContactTime] = localOpt(best,0,range(-10,45,5)) # jiggle inc to fine tune orbit path between ground stations
    [best, bestContactTime] = localOpt(best,4,range(0,360,10)) # jiggle ma to improve orbit starting point
    [best, bestContactTime] = localOpt(best,5,[x/10.0 for x in range(-20,30,1)]) # jiggle mm to try to increase dwell time with a higher orbit
    [best, bestContactTime] = localOpt(best,2,range(-500000,1000000,100000)) # fine tune ecc to squeeze out a bit more dwell time

    #print(f"Best: {best}, Contact time: {bestContactTime}")
    return best

if __name__ == "__main__":
    
    
    # get host from environment
    hostname = os.getenv("CHAL_HOST")
    if not hostname:
        print("No HOST supplied from environment")
        sys.exit(-1)

    # get port from environment
    port = int(os.getenv("CHAL_PORT","0"))
    if port == 0:
        print("No PORT supplied from environment")
        sys.exit(-1)

    
    # get ticket from environment
    ticket = os.getenv("TICKET")

    r = remote( hostname , port )
    
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline(bytes(ticket, 'utf-8'))    

    # Manually tuned parameters that do pretty well, 222 minutes
    #[inc,raan,ecc,aop,ma,mm] = [45, 45, 2000000, 270, 70, 10.6]

    # Numerically solved parameters that do even better, 238 minutes
    [inc,raan,ecc,aop,ma,mm] = [55, 20, 2400000, 300, 80, 10.5]
    # Run if you want to see how the parameters were created
    #[inc,raan,ecc,aop,ma,mm] = solve()

    # Send solution 
    r.recvuntil(b'Inclination (deg):')
    r.sendline(f"{inc}")
    r.recvuntil(b'RAAN (deg):')
    r.sendline(f"{raan}")
    r.recvuntil(b'Eccentricity (x10^-7):')
    r.sendline(f"{ecc}")
    r.recvuntil(b'Argument of perigee (deg):')
    r.sendline(f"{aop}")
    r.recvuntil(b'Mean anomaly (deg):')
    r.sendline(f"{ma}")
    r.recvuntil(b'Mean motion (revs/day):')
    r.sendline(f"{mm}")
    #r.recvuntil(b'flag{')
    r.recvall()
    #flag = r.recvall()
    #print("flag{"+str(flag, 'UTF-8'))
    