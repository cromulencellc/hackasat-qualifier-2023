import skyfield.api as sf
import ctf.io 
import ctf.challenge
import ctf.timeout 
import random
import numpy as np
ts = sf.load.timescale()

class ValidError( Exception ):
    pass

def exact( a , b , s=""):
    if( a != b ):
        ctf.io.outputStr(f"{s}: BAD")
        return False
    else:
        ctf.io.outputStr(f"{s}: OK")
        return True
def near( a, b , tolerance , s=""):
    close = np.isclose( a, b , atol=tolerance)
    if( not close ):
        ctf.io.outputStr(f"{s}: BAD")
        return False
    else:
        ctf.io.outputStr(f"{s}: OK")
        return True
def printAnswers( sat ):
    ctf.io.outputStr("I parsed your TLE and it has the following values")
    ctf.io.outputStr(f"Satellite nuber: {sat.model.satnum}")
    ctf.io.outputStr(f"Classification: {sat.model.classification}")
    ctf.io.outputStr(f"Designator: {sat.model.intldesg}")
    ctf.io.outputStr(f"B*: {sat.model.bstar}")
    ctf.io.outputStr(f"Epoch Year: {sat.model.epochyr}")
    ctf.io.outputStr(f"Epoch Day of Yr: {sat.model.epochdays}")
    ctf.io.outputStr(f"Inclination: {sat.model.inclo} rad")
    ctf.io.outputStr(f"RAAN: {sat.model.nodeo} rad")
    ctf.io.outputStr(f"Argument of Periapsis: {sat.model.argpo} rad")
    ctf.io.outputStr(f"Mean Anomaly: {sat.model.mo} rad")
    ctf.io.outputStr(f"Eccentricity: {sat.model.ecco} ")
    ctf.io.outputStr(f"Semimajor Axis: {sat.model.a* sat.model.radiusearthkm} km")
def evaluate( sat1 , sat2 ):
    #Line 1 tests
    ok = False
    
    numOk = exact( sat1.model.satnum,  sat2.model.satnum, "Satellite Number")
    classOk = exact( sat1.model.classification , sat2.model.classification, "Classification" )
    exact( sat1.model.intldesg ,sat2.model.intldesg , "International Designator")
    #near( sat1.model.ndot , sat2.model.ndot , 1e-15)
    #near( sat1.model.nddot , sat2.model.nddot , 1e-16)
    bstarOk = near( sat1.model.bstar , sat2.model.bstar , 0.0001, "B*")
    epochYrOk = exact( sat1.model.epochyr, sat2.model.epochyr, "Epoch Year" ) 
    epochDayOk = near( sat1.model.epochdays, sat2.model.epochdays, 1.16e-5, "Epoch Days") 
    # Angles
    iOk    = near( np.rad2deg(sat1.model.inclo)   , np.rad2deg( sat2.model.inclo ) , 0.5, "Inclination")
    nodeOk = near( np.rad2deg(sat1.model.nodeo)   , np.rad2deg( sat2.model.nodeo ), 0.05, "Right Ascension")
    argOk  = near( np.rad2deg(sat1.model.argpo)   , np.rad2deg( sat2.model.argpo) , 0.1, "Argument Periapsis")
    mOk    = near( np.rad2deg(sat1.model.mo)      , np.rad2deg( sat2.model.mo ), 0.1   , "Mean Anomaly")
    eOk = near( sat1.model.ecco    ,sat2.model.ecco , 0.00015, "Eccentricity")
    RE = sat1.model.radiusearthkm
    aOk = near( sat1.model.a*RE,  sat2.model.a*RE , 0.1, "Semimajor axis")
    # 
    ok = ( numOk == True )      and \
         ( classOk == True )    and \
         ( bstarOk == True )    and \
         ( epochYrOk == True )  and \
         ( epochDayOk == True)  and \
         ( iOk == True )        and \
         ( nodeOk == True )     and \
         ( argOk  == True)      and \
         ( mOk == True )        and \
         ( eOk == True )        and \
         ( aOk == True)
    return ok
# Do not move this or change the number here - it takes some time to solve tis so 
# We are doing the timeout on each attempt and giving people plenty o time
@ctf.timeout.timeout( 200 )
def single(  tle ):
    satellites = sf.load.tle_file(tle)
    
    sat = satellites[0]
    ctf.io.outputStr(f"The satellite we are monitoring is {sat}")
    # We're only supporting U/S
    c = "Unclassified" if sat.model.classification == 'U' else "Secret"
    ctf.io.outputStr(f"This satellite is {c}")
    launchYear = sat.model.intldesg[0:2]
    launchNo = sat.model.intldesg[2:5]
    launchPart = sat.model.intldesg[5]
    ctf.io.outputStr(f"This satellite was part {launchPart} of the {launchNo} launch of the year 20{launchYear} ")
    ctf.io.outputStr("Here are the position vectors of the satellite in ICRS")
    ctf.io.outputStr("Time, X (km), Y (km), Z(km)")
    ctf.io.outputStr("--------------------------")
    
    t0 = sat.epoch 
    t1 = sat.epoch + 7 # days
    times = ts.linspace( t0 , t1 , 200 )
    for t in times:
        pvt = sat.at(t)
        pos = pvt.position.km
        outStr = np.array2string( pos , separator=",")
        outStr = outStr.strip("[]")
        ctf.io.outputStr(f"{t.utc_strftime()},{outStr}")

    tle1 = ctf.io.input_str("What is TLE line 1: ")
    tle2 = ctf.io.input_str("What is TLE line 2: ")

    try:
        answer = sf.EarthSatellite(tle1, tle2, 'Answer', ts)
    except:
        ctf.io.outputStr("TLE Error")
        raise ValidError
    printAnswers( answer)
    ctf.io.outputStr("Checking answer")
    ok = evaluate( sat , answer )
    return ok


    pass


def chal( ):
    chal = ctf.challenge.Challenge()
    tle0 = ["sat1.tle"]
    tle_i = ["sat2.tle","sat3.tle","sat4.tle"]
    #random.shuffle( tle_i )
    ctf.io.outputStr("I'll give you positions you give me TLEs")
    ctf.io.outputStr("These positions match TLEs if you propegate with SGP4")
    ctf.io.outputStr("I wont validate your checksums :)")
    tles = tle0 + tle_i
    countOk = 0 
    for tle in tles:
        ok = single( tle )
        if( ok == False ):
            return False
        else: 
            countOk += 1
    if countOk == len( tles):
        ctf.io.outputStr("Thanks for your spacemath")
        ctf.io.outputStr( chal.getFlag() )
    else:
        ctf.io.outputStr("You should never get here - if you do contact admin")
if __name__ == "__main__":
    
    try:
        chal( )
    except ctf.timeout.TimeoutError:
        ctf.io.outputStr("Timeout")
    ctf.io.outputStr("Bye.")