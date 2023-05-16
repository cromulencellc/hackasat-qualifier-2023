import jinja2
import numpy as np
import datetime 
class CesiumOrbitTemplate:
    def __init__(self):
        self.time_format = "%Y-%m-%dT%H:%M:%SZ"
        self.gs = []
        pass
    def add_groundstation( self , name,lat,long,altitude ):
        latRad = lat * np.pi/180.0
        lonRad = long * np.pi/180.0
        R = 3396000
        xy = np.cos( latRad ) * R 
        z  = np.sin( latRad ) * R
        #
        x = np.cos( lonRad ) * xy 
        y = np.sin( lonRad ) * xy  

        gs = {
            "name":name,
            "X":x,
            "Y":y,
            "Z":z,
        }
        self.gs.append(gs )
    def set_orbit( self , fixedDataArray, inertialDataArray, decimation=1 ):
        self.fixed = []
        self.inertial = []
        count = 0
        for fixed in fixedDataArray:
            count = count+1
            entry = dict()
            entry["X"] = fixed["X"]*1000
            entry["Y"] = fixed["Y"]*1000
            entry["Z"] = fixed["Z"]*1000
            entry["time"] = fixed["time"].strftime( self.time_format )
            if(  (count  % decimation ) == 0 ):
                self.fixed.append(entry)
        for inertial in inertialDataArray:
            count = count+1
            entry = dict()
            entry["X"] = inertial["X"]*1000
            entry["Y"] = inertial["Y"]*1000
            entry["Z"] = inertial["Z"]*1000
            entry["time"] = inertial["time"].strftime( self.time_format )
            if(  (count  % decimation ) == 0 ):
                self.inertial.append(entry)
        pass
    def set_window( self ,startTime , stopTime):
        #"2014-07-22T11:29:11Z"
        
        self.start = startTime.strftime(self.time_format)
        self.stop = stopTime.strftime(self.time_format)
    def render( self  , template_directory, template_filename , out_path , name ):
        templateLoader = jinja2.FileSystemLoader(searchpath= template_directory )
        templateEnv = jinja2.Environment(loader=templateLoader)
        template = templateEnv.get_template(template_filename)
        out_text = template.render( start_time=self.start, stop_time = self.stop , point=self.inertial, path=self.inertial, name=name , gslist=self.gs)  
        new_file = open( out_path , "wt")
        new_file.write( out_text )
        new_file.close()
