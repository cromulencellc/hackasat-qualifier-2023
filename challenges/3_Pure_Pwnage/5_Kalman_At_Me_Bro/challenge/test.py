import data
import numpy as np
import filter
def run():
    d = data.Data( 101 )
    accels = d.genAccel(0 )# 0.1)
    positions = d.genPos( 0 , 100)
 # Dump data
    d.dumpAccel( "accels.bin")
    d.dumpPositions( "positions.bin")
    kf = filter.FilterPython( )
    p = np.transpose( positions[0]['pos'] ).flatten()
    
    kf.init( p,  np.array([0,0,0]))
    kf.run( accels=accels, positions=positions)

if __name__ == "__main__":
    run()