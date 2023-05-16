def beam_pattern_1d( locations  , steerTo):
    # shifter values
    shifts = []
    for loc in locations:
        D = loc * np.cos( np.radians( steerTo ))
        phase = -D * np.pi * 2.0 
        shifts.append( phase  )
    phaseSteering = np.array( shifts  )
    cpxPhaseSteering = np.exp( 1j* phaseSteering )

    # locations is in wavelengths
    arrivalAnglesDeg = np.array([45]) 
    arrivalAnglesDeg = np.arange( 0 , 180 , 0.5 )
    
    
    # Loop over all angles of arrival 
    sums = []
    for aoa in arrivalAnglesDeg:
        waveFrontDistances = np.cos(  np.radians(aoa) ) * locations # in wavelengths 
        waveFrontPhases =  ( waveFrontDistances / 1.0 ) * 2 * np.pi  # radians

        cpxPhasePhysics = np.exp( 1j*waveFrontPhases)

        summation = np.sum( cpxPhasePhysics * cpxPhaseSteering ) 
        pow = summation * np.conj( summation )
        sums.append(  pow )
    # 
    maxPow = [(len( LOCATIONS))**2 ] * len( arrivalAnglesDeg)
    plt.plot( arrivalAnglesDeg , maxPow ,'r')
    plt.plot( arrivalAnglesDeg , sums)
    plt.show() 







if __name__ == "__main__":
    