from skyfield.api import Star, load
from skyfield.data import hipparcos
from skyfield.api import N,S,E,W, wgs84
from alive_progress import alive_bar

ts = load.timescale()
planets = load('de421.bsp')

class StarError(Exception):
    pass

class StarObservatory:
    def __init__( self , latDegrees, longDegrees , altitude , catalog ):
        self.lat = latDegrees * N
        self.lon = longDegrees * E 
        
        self.catalog = catalog

        earth = planets['earth']
        self.observatory = earth + wgs84.latlon( self.lat , self.lon , elevation_m=altitude)
    def verifyVisible( self, time, stars ):
        t = ts.from_datetime( time )

        visible = 0 
        inView = {}
        nStars = self.catalog.shape[0]
        print("Verifying visiblity")
        with alive_bar( nStars) as bar:
            for hipocrasIndex,row in self.catalog.iterrows():
                star = Star.from_dataframe(row)
                astrometric = self.observatory.at(t).observe(star)
                astro = astrometric.apparent()
                alt,az,distance = astro.altaz()
                if alt.degrees > 0:
                    visible += 1 
                    inView[ hipocrasIndex ] =  (az,alt, distance) 
                    pass
                bar()
        print(f"There are {visible} stars in view")
        
        if set(stars).issubset( set( inView.keys() )):
            print("The stars you picked are in view")
        else:
            print("Not all stars are in view")
        
        
        
    

    def getAzEl( self, catalogNumber , time ):
        t = ts.from_datetime( time )
        star_obj = Star.from_dataframe(self.catalog.loc[catalogNumber])

        astrometric = self.observatory.at(t).observe(star_obj)
        astro = astrometric.apparent()
        alt,az,distance = astro.altaz()
        if( alt.degrees < 0.0 ):
            print(f"Star {catalogNumber} not in view at time {time}")
            raise StarError
        return (alt,az,distance)