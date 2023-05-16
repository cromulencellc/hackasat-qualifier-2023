import matplotlib.pyplot as plt
from Basilisk.utilities import (SimulationBaseClass, macros, orbitalMotion,
                                simIncludeGravBody, unitTestSupport, vizSupport)




def BasicPlot( time , data ,yLabel, file  ):
    plt.figure(1)
    fig = plt.gcf()
    ax = fig.gca()
    ax.ticklabel_format(useOffset=False, style='plain')
    plt.plot( time , data )
    plt.xlabel('Time [hrs]')
    plt.ylabel( yLabel )
    #lt.show()
    plt.savefig(f"static/{file}")

