import numpy as np
def guessM0( measurements ):
    mm = [  m["pos"] for m in measurements ]
    posMat = np.matrix( mm )
    r = np.linalg.norm( posMat , axis=1)
    dr = np.diff( r )
    px,py,pz = periapsis(measurements)
    peri = np.array( [px,py,pz])
    r0 = measurements[0]["pos"]
    d = np.dot( r0 , peri )/ ( np.linalg.norm(r0) * np.linalg.norm(peri))
    # approximate m by assuming ecc = 0 which means TA = E = M
    m = np.arccos( d )
    # but we need to check if its negative or positive
    # if r is decreasing its negative - increasing positive
    if( r[0] > r[1] ):
        # negative
        m = 2*np.pi -m
    
    return m
def guessInc( measurements ):
    hunit = angmomentum( measurements )
    z = np.array([0, 0, 1 ])
    d = np.dot( hunit , z )
    i = np.arccos( d )
    return i
def guessRaan( measurements ):
    x,y,z = ascendingNode( measurements )    
    raan = np.arctan2( y, x)
    return raan
def ascendingNode( measurements ):
    mm = [ m["pos"] for m in measurements]
    posMat = np.array( mm )
    zAx = posMat[:,2].flatten()
    ind  = np.argmin( np.abs( zAx ))
    # determine if this is the ascending or descending nod
    if( zAx[ind] > zAx[ind-1]):
        # ascending node
        x = posMat[ind,0]
        y = posMat[ind,1]
        z = posMat[ind,2]
    else:
        #descending node - flip it
        x = -posMat[ind,0]
        y = -posMat[ind,1]
        z = -posMat[ind,2]

    return x,y,z
def angmomentum( measurements ):
    nx,ny,nz = ascendingNode(measurements )
    px,py,pz = periapsis(measurements)
    peri =np.array( [px,py,pz])
    node = np.array([nx,ny,nz])

    h = np.cross( node , peri )
    hunit = h / np.linalg.norm( h )
    return hunit

def periapsis( measurements ):
    mm = [  m["pos"] for m in measurements ]
    posMat = np.matrix( mm )
    r = np.linalg.norm( posMat , axis=1)
    ind = np.argmin( r )
    x = posMat[ind,0]
    y = posMat[ind,1]
    z = posMat[ind,2]
    return x,y,z
def apoapsis( measurements ):
    mm = [  m["pos"] for m in measurements ]
    posMat = np.matrix( mm )
    r = np.linalg.norm( posMat , axis=1)
    ind = np.argmax( r )
    x = posMat[ind,0]
    y = posMat[ind,1]
    z = posMat[ind,2]
    return x,y,z
def guessArgPeri( measurements ):
    nx,ny,nz = ascendingNode(measurements )
    px,py,pz = periapsis(measurements)
    peri =np.array( [px,py,pz])
    node = np.array([nx,ny,nz])
    d = np.dot( peri , node )  / ( np.linalg.norm(peri) * np.linalg.norm( node ))
    ang = np.arccos( d )
    return ang
def guessSmaEcc( measurements ):
    px,py,pz = periapsis( measurements )
    ax,ay,az = apoapsis( measurements )
    ra = np.linalg.norm( np.array([ax,ay,az] ))
    rp = np.linalg.norm( np.array([px,py,pz]))
    a = ( rp + ra) /2
    e = 1- (rp/a)
    return a,e 