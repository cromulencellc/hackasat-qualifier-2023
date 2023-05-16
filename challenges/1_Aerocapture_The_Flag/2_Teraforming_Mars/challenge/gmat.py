from multiprocessing.sharedctypes import Value
import os
import subprocess 
import numpy as np
from datetime import datetime,timezone
import jinja2
import skyfield.api as sf
class Gmat:
    def __init__( self , install ):
        self.time_format  = '%d %b %Y %H:%M:%S.%f'
        self.loc = install
        self.exe = os.path.join( install , "bin/GmatConsole")
    def run_script( self , script_path ):
        log = open("./log.txt","wt")
        error = open("./error.txt","wt")
        script_abs_path = os.path.abspath( script_path )
        gmat_command = ["./GMAT/R2020a/bin/GmatConsole" , "--run", script_abs_path]
        gmat_process = subprocess.Popen( gmat_command , stdout=log , stderr=error )
        gmat_process.communicate()
    

        
    def get_log( self , logname ):
        path_to_log = os.path.join( self.loc , "output" , logname )
        my_data = np.genfromtxt(path_to_log, skip_header=1, delimiter=',', names=["time","X","Y","Z","VX","VY","VZ"], dtype=["S100", "f8", "f8", "f8", "f8", "f8", "f8"])
        out = [ ]
        for item in my_data:
            data = dict() 
            ts = item["time"].decode('utf-8')
            dt = datetime.strptime(ts  , self.time_format )
            dt = dt.replace( tzinfo=timezone.utc)
            
            data['time'] = dt
            data["X"] = item["X"]
            data["Y"] = item["Y"]
            data["Z"] = item["Z"]
            data["VX"] = item["VX"]
            data["VY"] = item["VY"]
            data["VZ"] = item["VZ"]

            out.append( data )
            
    
        return out 

class GmatTeplate:
    def __init__(self):
        self.data = dict()
        self.data["maneuvers"] = []
        self.ts = sf.load.timescale()
        self.mjd_epoch = 2430000.0 # This is in the gmat doc
        self.logs = []
        self.gs = []
    def set_start_stop( self , start , stop ):
        s0 = self.ts.from_datetime( start )
        sf = self.ts.from_datetime( stop )
        self.epoch = s0.tt - self.mjd_epoch
        self.stop = sf.tt - self.mjd_epoch
    def add_groundstation( self, name ,lat ,long,altitude ):
        new_gs = {}
        new_gs["name"] = name
        new_gs["latitude"] = lat
        new_gs["longitude"] = long
        new_gs["altitude"] = altitude
        self.gs.append( new_gs )
    def add_maneuver( self , maneuver_string ):
        if( "\n" in maneuver_string ):
            print("Maneuver string passed with with multiple lines - this parameter is a single line string")
            raise ValueError
        entries = maneuver_string.split(",")
        if( len(entries) != 4  ):
            print("Maneuver passed that doesnt follow format: Time,∆Vx,∆Vy,∆VZ")
            raise ValueError
        # it might actually be ok!    
        time_str = entries[0]

        try:
            dt_maneuver = datetime.strptime( time_str , """%Y-%m-%d %H:%M:%S.%f""" )
            dt_maneuver = dt_maneuver.replace(tzinfo=timezone.utc)      
            t = self.ts.from_datetime( dt_maneuver )
            gmat_jd = t.tt - self.mjd_epoch
        except: 
            print(" Poorly formatted time entry in manuever {}".format( time_str ))
            raise ValueError
        try:
            dv = np.array( [float(entries[1]), float(entries[2]), float(entries[3])] ) 
        except:
            print("∆V entered: {} improperly formatted".format(maneuver_string))
            raise ValueError
        new_maneuver = dict()
        
        new_maneuver["prop_until"] = gmat_jd
        new_maneuver["delta_v"] = dv 
        self.data["maneuvers"].append( new_maneuver )
    def add_log( self , name , frame  , filename):
        newlog = dict()
        newlog["name"] = name
        newlog["frame"] = frame 
        newlog["filename"] = filename
        self.logs.append( newlog)
    def get_total_dv( self ):
        total_dv = 0.0
        for manuever in self.data["maneuvers"]:
            dv = manuever["delta_v"]
            total_dv = total_dv + np.linalg.norm( dv ) 
    
        return total_dv
    def validate_order( self ):
        last_time = self.epoch
        for maneuver in self.data["maneuvers"]:
            time = maneuver["prop_until"]

            if( last_time > time):
                return False
            last_time = time
        return True
    def render( self  , template_directory, template_filename , out_path ):
        templateLoader = jinja2.FileSystemLoader(searchpath= template_directory )
        templateEnv = jinja2.Environment(loader=templateLoader)
        template = templateEnv.get_template(template_filename)
        out_text = template.render( stop_time = self.stop , manuever_list=self.data["maneuvers"] , logs=self.logs, gs_list=self.gs)  
        new_file = open( out_path , "wt")
        new_file.write( out_text )
        new_file.close()
class TimeOrderError(Exception):
    pass
