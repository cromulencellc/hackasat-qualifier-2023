from skyfield.api import Star, load
from skyfield.data import hipparcos
import numpy as np
from skyfield.api import N,S,E,W, wgs84
from scipy.spatial.transform import Rotation as R
import itertools 

with load.open(hipparcos.URL) as f:
    starCatalog = hipparcos.load_dataframe(f)
AU_PER_LY = 63241.1
ts = load.timescale()
planets = load('de421.bsp')
def columnRotHelper( axis , angle ):
    return np.squeeze(R.from_euler( axis, [angle],degrees=True).as_matrix()).transpose()

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

def stars_in_view(  time , lat , lon , alt, maxLy  ):
    print(f"Finding all stars within {maxLy} LY")
    nearStars = nearestStars( maxLightYears=maxLy) 
    observer = planets["earth"] + wgs84.latlon( lat ,lon , alt)
    inView = {}
    t = ts.from_datetime( time )
    for hipocrasIndex,row in nearStars.iterrows():
        star = Star.from_dataframe(row)
        astrometric = observer.at(t).observe(star)
        astro = astrometric.apparent()
        alt,az,distance = astro.altaz()
        if alt.degrees > 0:
            inView[ hipocrasIndex ] =  (az,alt, distance) 
            pass
    return inView

class Viewer():
    def __init__( self , lat,lon,alt , maxLy ):
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.maxLy = maxLy
        self.observer = planets["earth"] + wgs84.latlon( lat ,lon , alt)
        self.nearestStars = nearestStars( maxLy )
        
    def observe_at( self , time  ):
        inView = {}
        t = ts.from_datetime( time )
        visible = 0
        for hipocrasIndex,row in self.nearestStars.iterrows():
            star = Star.from_dataframe(row)
            astrometric = self.observer.at(t).observe(star)
            astro = astrometric.apparent()
            alt,az,distance = astro.altaz()
            if alt.degrees > 0:
                visible += 1 
                inView[ hipocrasIndex ] =  (az,alt, distance) 
        self.inView = inView
    def get_distance( self, starId ):
        return self.inView[starId][2]
    def nearest( self, az, el , Nlimit ):
        # LOS
        los_LOS_Frame = np.array( [1,0,0] )
        # Calculate LOS for the proposed az el:
        look_azRot = columnRotHelper("x", -az )
        look_elRot = columnRotHelper("y",-(90.0-el))
        look_UEN_2_LOS = np.matmul( look_elRot,  look_azRot )
        look_LOS_2_UEN  = look_UEN_2_LOS.transpose()
        look_los_UEN_FRAME = np.matmul( look_LOS_2_UEN , los_LOS_Frame )
        
        # Calculate Los for every star
        offset ={}
        for id,star in self.inView.items():
            azStar= star[0].degrees
            elStar = star[1].degrees
            azRot = columnRotHelper("x", -azStar )
            elRot = columnRotHelper("y",-(90.0-elStar))
            UEN_2_LOS = np.matmul( elRot,  azRot )
            LOS_2_UEN  = UEN_2_LOS.transpose()
            los_LOS_Frame = np.array( [1,0,0] )
            los_UEN_FRAME = np.matmul( LOS_2_UEN , los_LOS_Frame )

            diffDeg = np.arccos( np.dot( look_los_UEN_FRAME , los_UEN_FRAME )) * 180.0 / np.pi
            offset[id] =  diffDeg , star[2].au 
            
        sortedAngles = dict(sorted(offset.items(), key=lambda item: item[1][0]))

        return dict(itertools.islice(sortedAngles.items(), Nlimit)) 
        