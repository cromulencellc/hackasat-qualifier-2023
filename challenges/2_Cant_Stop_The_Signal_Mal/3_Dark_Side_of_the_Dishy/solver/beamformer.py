import numpy  as np
from scipy.spatial.transform import Rotation as R

def columnRotHelper( axis , angle ):
    return np.squeeze(R.from_euler( axis, [angle],degrees=True).as_matrix()).transpose()


def adaptive(  pilots , signals ):
    nPilots = len( pilots )
    p = np.transpose( np.matrix( pilots ) ) 
    Y = np.transpose( np.matrix( signals[:,:nPilots] )  ) 
    w = np.linalg.inv( Y.H @ Y ) @ Y.H @ p 
    return w 
def azElToWaveDelay( azDegrees, elDegrees , locations ):
    azRot = columnRotHelper("x", -azDegrees )
    elRot = columnRotHelper("y",-(90.0-elDegrees))
    UEN_2_LOS = np.matmul( elRot,  azRot )
    LOS_2_UEN  = UEN_2_LOS.transpose()
    los_LOS_Frame = np.array( [1,0,0] )
    los_UEN_FRAME = np.matmul( LOS_2_UEN , los_LOS_Frame )
    waveDistances = []
    for idx,loc in  enumerate(locations):
        UEN = np.array( [0 , loc[0], loc[1] ] ) 
        waveDistance = np.dot( UEN , los_UEN_FRAME) # wavelengths
        waveDistances.append(waveDistance)
    return np.array( waveDistances ) 
def spatial_covariance( signals , N ):
    # For a vector of L signals
    L =signals.shape[1]
    # Calculate the spatial covariance based on N samples

    # Verify that we have enough 
    R = np.zeros(  (L,L), dtype=np.complex64 )
    for k in range(0,N):
        X =  signals[k,:] 
        Rk = X.H @ X
        R =  R + Rk 
    R = R / N
    return R
def dmr_spatial_covariance( signals, nSample, nReject):
    L = len(signals)
    
    R = spatial_covariance( signals, nSample )
    lam,v = np.linalg.eig( R )
    # dominant terms
    lam_d = lam[0:nReject]
    v_d = [ v[:,k] for k in range( nReject )] 
    lam_bkg = lam[nReject : ]
    v_bkg = [ v[:,k] for k in range( nReject , L)]
    # create the dominant covariance
    Rdom = np.zeros( (L,L), dtype=np.complex64)
    for LAM,V in zip( lam_d,v_d):
        Rdom += LAM * ( V @ V.H )
    # replace all other eigen values with consant bkg
    Rbkg = np.zeros( (L,L), dtype=np.complex64)
    bkgAvg = np.average( lam_bkg )
    for V in v_bkg:
        Rbkg += bkgAvg * ( V @ V.H )
    
    R = Rdom + Rbkg
    return Rdom + Rbkg

def mvdr( Rinv , v0  ):
    # MVDR beamformer
    # Capon gain to enforce unity
    alpha =( 1.0 / ( v0.H @ Rinv  @ v0 ) )
    alpha =  alpha.flatten().item(0)
    w = alpha * (Rinv @ v0)
    return alpha, w 
def mvdr_2d( Rinv, az,el, locations ):
    waveLengths = azElToWaveDelay( az,el,locations)
    phases = 2 *np.pi*waveLengths 
    v  =  np.exp(  1j* phases , dtype=np.complex64)
    v0 = np.matrix( v ).transpose()
    alpha,w = mvdr( Rinv ,v0  )
    pow = np.real( np.abs( alpha ) ) 
    return pow, w 

def mvdr_1d(  Rinv, angle , locations):
    waveLengths =  np.cos( np.radians( angle) ) *locations
    phases = 2 *np.pi*waveLengths 
    v  =  np.exp(  1j* phases , dtype=np.complex64)
    v0 = np.matrix( v ).transpose()
    alpha,w = mvdr( Rinv ,v0  )
    pow = np.real( np.abs( alpha ) ) 
    return pow, w 
