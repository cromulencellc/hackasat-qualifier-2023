import datetime
import pytz
from skyfield.api import Star, load
from skyfield.data import hipparcos
from skyfield.api import N,S,E,W, wgs84
import numpy as np 
STARS = [54035,38992, 68682,18774,108467]
FREQS = [1.0/10.0,  1.0/20.0 ,1.0/5.0 , 1/4.0 , 1/8.0 ]
OBSERVATION_TIME = datetime.datetime( 2023,1,1,10,0,0, tzinfo=pytz.utc)
OBSERVATORY_LLA = ( 18.3464 , -66.7528 , 498)
MAX_DISTANCE_LY = 100.0
PLANETS = load('de421.bsp')
AU_PER_LY = 63241.1
RF_FREQ = 10.0e9 # XBand Hz
ANTENNA_E_GRID = np.arange(-1,1,0.25)
ANTENNA_N_GRID = np.arange(-1,1,0.25)
ts = load.timescale()


with load.open(hipparcos.URL) as f:
    starCatalog = hipparcos.load_dataframe(f)


def nearestStars( maxLightYears ):
    maxAu = maxLightYears * AU_PER_LY 
    minParallaxRadians = np.arctan( 1.0 / maxAu )
    minParallaxDegrees = minParallaxRadians * 180.0 / np.pi 
    minParallaxArcSec = (3600/1.0) * minParallaxDegrees
    minParallaxMilliArcSec = ( 1000.0 / 1.0 ) * minParallaxArcSec
    # All parallaxes less than the limit are further than MAX_LIGHTYEARS
    sortedList = starCatalog["parallax_mas"] > minParallaxMilliArcSec
    nearCatalog = starCatalog[sortedList]
    return nearCatalog
def sortByDistance( starIds ):
    distances  = { }
    for id in starIds:
        star = Star.from_dataframe(starCatalog.loc[id])
        paralax_arcsec = star.parallax_mas / 1000.0
        paralax_deg = paralax_arcsec / 3600.0
        distance_au  = 1.0 / np.tan(  np.radians( paralax_deg ))
        distance_ly = distance_au / AU_PER_LY
        distances[id]=distance_ly
    sortedDistances = dict(sorted(distances.items(), key=lambda item: item[1]))
    return list( sortedDistances.keys() ) 
if __name__ == "__main__":
    catalog = nearestStars(100.0)
    x = sortByDistance( STARS )