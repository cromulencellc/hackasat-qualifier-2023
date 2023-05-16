import matplotlib.pyplot as plt
import stars
import datetime
import pytz
OBSERVATION_TIME = datetime.datetime( 2023,1,1,10,0,0, tzinfo=pytz.utc)
OBSERVATORY_LLA = ( 18.3464 , -66.7528 , 498)
MAX_DISTANCE_LY = 100.0

starField = stars.stars_in_view(OBSERVATION_TIME, OBSERVATORY_LLA[0], OBSERVATORY_LLA[1] , OBSERVATORY_LLA[2] , MAX_DISTANCE_LY)

az = [a.degrees for a,e,l in starField.values() ]
el = [e.degrees for a,e,l in starField.values() ]
plt.style.use('dark_background')
plt.figure(1)

plt.plot( az, el ,'.', markersize=1)
plt.xlabel("Azimuth (degrees)")
plt.ylabel("Elevation (degrees)")



plt.show()