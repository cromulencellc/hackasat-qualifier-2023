import sys
import time
import ctf.challenge as Challenge
import ctf.io as IO
import ctf.timeout as TO

import numpy as np
from skyfield.api import load, wgs84, EarthSatellite
from skyfield.toposlib import GeographicPosition

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

def render_intro():
    art = """
                                                                                 
   _|_|_|    _|_|    _|      _|  _|_|_|_|_|    _|_|      _|_|_|  _|_|_|_|_|  
 _|        _|    _|  _|_|    _|      _|      _|    _|  _|            _|      
 _|        _|    _|  _|  _|  _|      _|      _|_|_|_|  _|            _|      
 _|        _|    _|  _|    _|_|      _|      _|    _|  _|            _|      
   _|_|_|    _|_|    _|      _|      _|      _|    _|    _|_|_|      _|                                                                                 
                                                                            
    """
    print(art, end='')
    #time.sleep(1)

    text = """
    Billy Bob says he's the best orbit designer there's ever been. He designed an orbit with python skyfield that gets 230 minutes of contact on our ground station network.
    Can you beat him?
    
    Ground stations are located across the United States at these WGS-84 coordinates:
    Name                 Lat (deg)      Long (deg)       Alt (m)
"""
    for station in groundStations:
        text = text + f"    {station.name:16s}{station.pos.latitude.degrees:10.2f}{station.pos.longitude.degrees:15.2f}{station.pos.elevation.m:15.0f}\n"
    
    text = text + """
    Contact is established at 15 degrees above the horizon and with one ground station at a time.
    Our link budget supports a range of up to 6,000 km.
    Between 1 Apr 2023 00:00:00.000 UTC and 1 Apr 2023 08:00:00.000 UTC, get more hours of contact than Billy Bob.

    Good luck!

    """
    print(text)
    # for c in text:
    #     print(c, end='')
    #     #time.sleep(0.02) 
    return

def input_range(txt, min, max):
    while True:
        try:
            value = float(input(txt))
            if value < min or value > max:
                raise ValueError
            break
        except ValueError:
            print(f"\tEnter a value between {min} and {max}")
    return value


def take_inputs():
    print("Provide your TLE Line 2 parameters.")
    inc  = input_range('Inclination (deg):         ',0.0,180.0)   
    raan = input_range('RAAN (deg):                ',0.0,360.0)
    ecc  = input_range('Eccentricity (x10^-7):     ',0,9999999)
    aop  = input_range('Argument of perigee (deg): ',0.0,360.0)
    ma   = input_range('Mean anomaly (deg):        ',0.0,360.0)
    mm   = input_range('Mean motion (revs/day):    ',0.1,15.9)

    text = f"""
HACKASAT
1 75001F 23750A   23091.00000000  .00000000  00000-0  00000-0 0     1
2 75001 {inc:8.4f} {raan:8.4f} {ecc:0>7.0f} {aop:8.4f} {ma:8.4f} {mm:17.14f}
"""

    print("\nYour TLE:" + text)

    lines = text.strip().splitlines()
    try:
        sat = EarthSatellite(lines[1], lines[2], lines[0], ts)
    except Exception as e:
        print(e)
        print("Error loading TLE")

    return sat

def simulate(sat: EarthSatellite):
    t = sat.epoch
    dur = 8/24 # 8 hours
    dt = 1/24/60 # dt = 1 minute

    n = dur / dt

    print ("\nPreparing fiddle for orbit...")
    contactTime = 0
    contact = False

    i = 0
    while (i <= n):
        # Check ground station contacts
        satPos = sat.at(t).position.km
        if np.linalg.norm(satPos) <= 6378.14+300:
            print("Your satellite burned up in the atmosphere!! Keep it above 300km.")
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
                    print(f"{t.utc_strftime()}: {gnd.name} {A:3.2f} degrees elevation, {rMag:.2f}km range")

        if contact:
            contactTime += 1 # 1 minute

        #print(f"{t.utc_strftime()}:   {sat.at(t).position.km}")
        
        # Propagate satellite orbit
        t += dt
        i += 1

    # Return total contact time

    print(f"Your orbit achieved {contactTime} minutes of contact time")

    return contactTime

@TO.timeout(60*5) # CTF timeout decorator makes the function timeout
def main( ):
    f = Challenge.Challenge( ) # Use CTF package flag class to load the flag and cleanup the env
    render_intro()

    sat = take_inputs()

    contactTime = simulate(sat)
    
    if contactTime > 230:
        IO.outputStr("You beat Billy Bob, that son of gun!") 
        IO.outputStr( f.getFlag() )
    elif contactTime == 230:
        print("Wow it's a tie!! You're going to have to give it just a bit more, try again!!")
    else:
        print("Looks like Billy Bob is still the best orbit designer there's ever been. Better luck next time!")

if __name__ == "__main__":
    # Make sure to wrap main in a try/catch
    try:
        main( )
    except TO.TimeoutError:
        # print out some sort of error if things timeout
        IO.outputStr("\n\nTimeout --- bye\n\n")
