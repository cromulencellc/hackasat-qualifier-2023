import datetime
from skyfield.api import utc

import scipy.optimize as op
from sgp4.api import Satrec, WGS84
import skyfield.api as sf
import numpy as np
import batch
import copy
import guess
ts = sf.load.timescale()
A_SCALE = 6378
ECC_SCALE = 0.001
BSTAR_SCALE =0.1
def positive_mod( val , modulus ):
    return np.mod( val + modulus, modulus )
def fromString( dataStr ):
    dataLines = dataStr.decode().split("\n")
    measurements = []
    for line in dataLines:
        d = line.split(",")
        Tstr = d[0]
        t = datetime.datetime.strptime( Tstr, "%Y-%m-%d %H:%M:%S %Z")
        t = t.replace( tzinfo=utc)

        x = float(d[1])
        y = float(d[2])
        z = float(d[3])
        M = { "time": t,
              "pos": [x,y,z]
            }
        measurements.append(M)
    return measurements
def gen_tle(  data ):
    mu = 398600.8
    C = f"{data['num']:05}"
    CL = data['class']
    LY = f"{data['Lyear']:02}"
    LD = f"{data['Lnum']:03}"
    LP = data['Lpart']
    EY = f"{data['ey']:02}"
    ED = f"{data['ed']:012.8f}"
    B = f"{int(data['bstar']*1e5):05}"
    # 1 10000U 11080A   23052.42576006 -.00000072  00000+0  52001-1 0  9999
    DN = f"{0:.8f}"
    DDN = f"{0:08}"
    line1 = f"1 {C}{CL} {LY}{LD}{LP}   {EY}{ED} {DN} {DDN}  {B}-1 0  1000"
    #2 10000  52.0003 106.3271 0020436  98.1261 275.8872 12.62267363515735
    r = np.rad2deg( data['raan'])
    rS = f"{r:08.4f}"
    e = int(data['e']*1e7)
    eS = f"{e:07}"
    w = np.rad2deg( data['w'])
    wS = f"{w:08.4f}"
    i = np.rad2deg( data['i'])
    iS = f"{i:07.4f}"
    M = np.rad2deg( data['m'])
    MS = f"{M:08.4f}"
    a = data['a']
    # rad / sec 
    n = np.sqrt( mu / ( a * a * a))
    nD = n * (1 / (2*np.pi)) * 86400
    nS = f"{nD:2.8f}"  
    line2 = f"2 {C}  {iS} {rS} {eS} {wS} {MS} {nS}000000"
    try:
        test = sf.EarthSatellite(line1, line2, 'Answer', ts)
    except:
        print("FAIL")
    return line1,line2

class TleSolver:
    def __init__( self, data):
        self.measurements = data
        pass
    def estimate(self , epoch , catalog, classification,ly, lnum ,lpart):
        self.epoch = datetime.datetime.strptime(epoch,"%Y-%m-%d %H:%M:%S %Z")
        self.epoch = self.epoch.replace( tzinfo=utc)
        t = ts.from_datetime( self.epoch )
        # Our filter wont just magically converge with bad initial conditions
        # So we can do some real back of the napkin orbital mechanics to get 
        # close enough to the right answer
        # we'll be off - but the filter will solve the rest of the way
        raan0 = guess.guessRaan( self.measurements )
        w0    = guess.guessArgPeri( self.measurements )
        i0    = guess.guessInc( self.measurements )
        a0,e0 = guess.guessSmaEcc( self.measurements )
        m0    = guess.guessM0( self.measurements )
        Bstar0 = 1e-5/BSTAR_SCALE
        initial_guess = [Bstar0,e0/ECC_SCALE,w0,i0,m0,a0/A_SCALE,raan0]
     
        h = TleHelper( self.epoch)
        b = batch.BatchFilter( 7 , 3 ) # 7 states, 3 measurements
        b.init( initial_guess )
        b.measurment_fcn( h.TleToPos )
        b.jacobian_fcn( h.jacobian )
        for m in self.measurements:
            b.add_measurement( m["time"] , m["pos"])
        out = b.estimate( 20 )
        out = out.flatten()
        output_state( out )
        day = self.epoch.timetuple().tm_yday + (t.ut1_fraction-0.5)

        data = {
            "a": out[5]*A_SCALE,
            "e": out[1]*ECC_SCALE,
            "i": positive_mod(out[3], 2*np.pi),
            "raan":positive_mod(out[6],2*np.pi ),
            "w": positive_mod( out[2], 2*np.pi ),
            "m":positive_mod(out[4],2*np.pi ),
            "bstar":out[0],
            "num":catalog,
            "Lyear":ly%100,
            "Lnum":lnum,
            "Lpart":lpart,
            "ey":self.epoch.year%100,
            "ed":day,
            "class":classification


        } 
        l1,l2 = gen_tle( data )
        return l1,l2
def output_state(  state ):
    print(f"a: {state[5]*A_SCALE} km")
    print(f"e: {state[1]*ECC_SCALE}")
    print(f"i: {np.rad2deg(state[3])} deg")
    print(f"w: {np.rad2deg(state[2])} deg")
    print(f"RAAN: {np.rad2deg(state[6])} deg")
    print(f"M0: {np.rad2deg(state[4])} deg")
    print(f"B*: {state[0]*BSTAR_SCALE}")
class TleHelper:
    def __init__( self , epoch):
        self.epoch = epoch
        self.tsEpoch = ts.from_datetime( epoch )
        d = datetime.datetime( 1949, 12 ,31 ,0,0,27)
        d = d.replace(tzinfo=utc)
        self.t0 = ts.from_datetime( d )
    def TleToPos(self, t, x):
        # 
        mu = 398600.432896939
        tt = ts.from_datetime( t )
        a = x[5] * A_SCALE # x[7] is sma in earth radii
        ecco = x[1] * ECC_SCALE
        bstar =x[0] * BSTAR_SCALE
        no_kozai = np.sqrt( mu / (a*a*a) ) * 60 
        dt = self.tsEpoch - self.t0 
        satrec = Satrec()
        satrec.sgp4init(
        WGS84,           # gravity model
        'i',             # 'a' = old AFSPC mode, 'i' = improved mode
        10,               # satnum: Satellite number
        dt,       # epoch: days since 1949 December 31 00:00 UT
        bstar,      # bstar: drag coefficient (/earth radii)
        0, # ndot: ballistic coefficient (revs/day)
        0,             # nddot: second derivative of mean motion (revs/day^3)
        ecco,       # ecco: eccentricity
        x[2], # argpo: argument of perigee (radians)
        x[3], # inclo: inclination (radians)
        x[4], # mo: mean anomaly (radians)
        no_kozai, # no_kozai: mean motion (radians/minute)
        x[6], # nodeo: right ascension of ascending node (radians)
        )
        sat = sf.EarthSatellite.from_satrec( satrec ,ts)        
        o = sat.at( tt )
        pos = o.position.km
        pos.shape = (3,1)
        if( not np.any( np.isfinite( pos ))):
            print("wut")
        return pos
    def jacobian( self , t, x):
        # The partial derivatives for sgp4 are quite complex
        # Lets try to calculate this stuff numerically
        H = np.zeros( (3, 7 ))
        # Bstar
        dAng = 0.001
        H[:,0] = self.deriv( t, x , 0,  0.001) # Bstar
        #H[:,1] = self.deriv( t, x , 1,  1e-10) # ndot
        #H[:,2] = self.deriv( t, x , 2,  1e-10) #nddot
        H[:,1] = 10*self.deriv( t, x , 1,  0.001) # ecc
        H[:,2] = 0.7*self.deriv( t, x , 2,  dAng) # argp 
        H[:,3] = self.deriv( t, x , 3,  dAng) # incl
        H[:,4] = self.deriv( t, x , 4,  dAng) # Mean anom
        H[:,5] = 0.7*self.deriv( t, x , 5,  0.001)# nokazi
        H[:,6] = self.deriv( t, x , 6,  dAng) # Raan
        
        if(not np.all( np.isfinite(H) ) ):
            print("NAN or cpx")
        return H
    def deriv( self , t,  x , n , dx ):
        X0 = copy.copy( x )  
        X1 = copy.copy( x )  
        X2 = copy.copy( x )  
        # Perterub
        X2[n] = x[n]+dx
        X0[n] = x[n]-dx

        Y0 = self.TleToPos( t , X0 )
        Y1 = self.TleToPos( t , X1 )
        Y2 = self.TleToPos( t , X2 )

        dY = Y2-Y0
        
        dydx = dY / (2*dx)
        if( not np.all( np.isfinite( dydx ))):
            print("dafuq")
        return np.transpose( dydx ) 


if __name__ == "__main__":
    data = {
            "a":7000,
            "e": .01111,
            "i": .1,
            "raan":.2,
            "w": .3,
            "m":5,
            "bstar":0.11,
            "num":20,
            "Lyear":23,
            "Lnum":10,
            "Lpart":"A",
            "ey":23,
            "ed":10.111,
            "class":"U"


        } 
    l1,l2 = gen_tle( data )
    f = open("data.txt","rb")
    dataStr =f.read() 
    data = fromString( dataStr )
    t = TleSolver( data )
    epoch = "2023-02-21 10:13:06 UTC"
    t.estimate( epoch )