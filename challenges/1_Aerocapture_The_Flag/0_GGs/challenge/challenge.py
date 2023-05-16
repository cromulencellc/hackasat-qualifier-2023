import ctf.io
import ctf.challenge
import ctf.timeout
import ploty
import gravSat 
import numpy as np
import sys
from scipy.spatial.transform import Rotation as R
import random
import web
import time
import secrets
import multiprocessing
def randomInertia(  I ,  zRange, yRange, xRange ):
    z = random.randrange(  zRange[0] , zRange[1])
    y = random.randrange(  yRange[0] , yRange[1])
    x = random.randrange(  xRange[0] , xRange[1])
    s = R.from_euler('zyx', [z,y,x], degrees=True)
    DCM = s.as_matrix()
    DCM_T = np.transpose( DCM )
    out = np.matmul( DCM_T , np.matmul( I  , DCM ) ) 
    return out
def getInertias( ):

    I_base = np.matrix( [100,0,0,
                         0, 500,0,
                         0, 0, 500
                         ])
     
    I_base.shape =  (3,3) 
    I0 = I_base
    I1 = randomInertia( I_base , (30,70) , (20,50), (120,140))
    I2 = randomInertia( I_base , (120,140) , (60,70), (40,70))
    I3 = randomInertia( I_base , (20,30) , (30,50), (130,140))
    I4 = randomInertia( I_base , (65,80) , (10,20), (120,130))
    I5 = randomInertia( I_base , (30,70) , (30,70), (30,70))
    out = [I0, I1,I2,I3,I4, I5]
    return out
@ctf.timeout.timeout( 1000 )
def challenge( ):
    
    chal = ctf.challenge.Challenge( )
    plotPort =chal.getPort()
    plotHost =chal.getHost()
    seed = secrets.randbelow( 2 ** 64 )
    random.seed( seed )
    ctf.io.outputStr(f"Randomizing challenge with seed: {seed}")
    url = f"http://{plotHost}:{plotPort}"

    I = np.identity(3)
    nOrbits =10 
    accuracyDeg = 25
    nadirTolerance = 10
    initOffset = 10
    #  Print the prompt
    prompt ="""We're deploying a satellite to Geostationary orbit and our engineers told us that we dont need an ADCS system.
However, the earth observing radio sensor we are using is directional and must always be pointing close to NADIR. 
"""
    ctf.io.outputStr(prompt)
    # print the rules
    ctf.io.outputStr("You may put the radio sensor facing any direction you want on the spacecraft")
    ctf.io.outputStr(f"We will evaluate the satellites pointing for {nOrbits} orbits")
    ctf.io.outputStr(f"The antenna must remain within {nadirTolerance} degrees of NADIR.")
    ctf.io.outputStr(f"The launch vehcile company said they will deploy our satellite with the antenna facing NADIR and an angular velocity matching the earth's rotation")

    correctCount = 0
    
    multiInertia = getInertias()
    # Run 5 random ones
    for inertia in multiInertia :
        I = np.asarray( inertia )
        ok = runSingle(I, nOrbits , nadirTolerance, url) 
        if( False == ok ):
            return
        else:
            ctf.io.outputStr("Good --- lets design another satellite.")

            correctCount += 1
    if( correctCount == (len(multiInertia))):
        ctf.io.outputStr("Wow I guess we didnt need the ADCS after all")
        ctf.io.outputStr( chal.getFlag() )
    else: 
        ctf.io.outputStr("You should never get here---if you do contact an admin")
    
    

def runSingle( inertia , orbits, accuracy , url ):
    
    ctf.io.outputStr(f"The intertia matrix for this satellite is \n {inertia} kg-m^2")
    axis = ctf.io.input_number_array( "Which body fixed axis would you like to mount the antenna ( eg: x,y,z ) : ", 3)

    ctf.io.outputStr("Normalizing the axis")
    unitAxis = axis / np.linalg.norm( axis )
    
    ctf.io.outputStr(f"Pointing axis {unitAxis} NADIR.")
    ctf.io.outputStr(f"Propegating for {orbits} orbits. This may take a some time...please wait")
    
    g = gravSat.GravSat( unitAxis , inertia )
    t,angle,gg = g.run( orbits )
    angleDeg = np.rad2deg( angle )
    ok = check_angles( t,angleDeg, accuracy)

    if( ok ):
        pass
    else:
        # lets make a plot
        showTime = 100
        
        ploty.BasicPlot( t , angleDeg , "Angle off NADIR (deg)" , "angle.png")

        p = multiprocessing.Process( target=web.run_web , daemon=True)
        ctf.io.outputStr(f"Plot available at {url} for {showTime} sec")
        p.start()
        time.sleep( showTime )
        return False
    #ploty.BasicPlot( t , gg , "Angle off NADIR (deg)" , "angle.png")
def check_angles( times, angles, toleranceDeg ):
    for t,a in zip(times,angles):
        # make sure its actually a number
        if( False == np.isreal( a ) ):
            ctf.io.outputStr(f"At time {t} angle to nadir is {a} which is not a real number...contact admin")
            raise ValueError
       
        if( a > toleranceDeg):
            ctf.io.outputStr(f"At time {t} angle to nadir is {a} (deg) which is greater than {toleranceDeg} (deg).")
            ctf.io.outputStr("Failed")
            return False
    return True



if __name__ == "__main__":
    try:
        challenge() 
    except ctf.timeout.TimeoutError:
        ctf.io.outputStr("Timeout")
    print("Bye...")