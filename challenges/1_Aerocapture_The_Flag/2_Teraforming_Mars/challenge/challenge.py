import numpy as np
import sys
import os
from datetime import datetime, timezone
import ctf.timeout as TO
import ctf.io as IO
import ctf.challenge as CHALLENGE
import cesium
import gmat

# Default timeout is set to 240 just in case gmat runs slower on the load

class OrbitError( Exception ):
    pass
class HighOutOfBounds( Exception ):
    pass
class LowOutOfBounds( Exception ):
    pass
@TO.timeout(300)
def challenge(  ):
    MarsRadius = 6700
    MarsSystem = 200000
    TerraformerRange = 100000
    communication_start_date = datetime( year=2024 , month=10 , day=4,hour=12, tzinfo= timezone.utc )
    start_date = datetime( year=2024, month=10 , day=1, hour=12, tzinfo= timezone.utc)
    stop_date = datetime( year=2025 , month=10,  day=1 , tzinfo= timezone.utc)
    dv_limit = 2.8
    # booster conditions:
    t = "01 Oct 2024 12:00:00.000"
    a = -4782.646575482534
    e = 4.562837706706173
    inc = 25.85702674260729
    raan = 243.2894523568879
    aop = 167.6140637297613
    TA = 260
    # terraformer
    latitude = 40.8
    longitude =  -9.6
    altitude = 0
    
    #
    gmat_exe = gmat.Gmat("./GMAT/R2020a")
    gmat_template = gmat.GmatTeplate()
    
    gmat_template.set_start_stop( start_date , stop_date )
    gmat_template.add_groundstation( "Terraformer", latitude, longitude, altitude )
    gmat_template.add_log('Satellite', "MarsFixed", "sat_mars_fixed")
    gmat_template.add_log('Satellite', "MarsInertial", "sat_mars_inertial")
    gmat_template.add_log('Satellite', "TerraformerUpFrame" , "sat_terraformer")
    service_port = os.getenv("SERVICE_PORT",12000)
    service_host = os.getenv("SERVICE_HOST","localhost")
    IO.outputStr("Please put our communication satellite in contact with the terraforming colony")
    IO.outputStr("You may assume all celestial bodies are point masses") 
    IO.outputStr("The orbital elements for the satellite with respect to the Mars Centered ICRF frame: ")
    IO.outputStr("Gregorian TT: {} ".format(t))
    IO.outputStr("Semimajor axis: {} km".format(a))
    IO.outputStr("Eccentricity: {}".format(e))
    IO.outputStr("Inclination: {} deg".format( inc ))
    IO.outputStr("RAAN: {} deg".format( raan ))
    IO.outputStr("Argument of periapsis: {} deg".format(aop))
    IO.outputStr("True Anomaly: {} deg".format(TA))
    IO.outputStr("--------------------------------------------")
    IO.outputStr("The terraformer is at: ")
    IO.outputStr(f"Latitude: {latitude} deg")
    IO.outputStr(f"Longitude: {longitude} deg")
    IO.outputStr("--------------------------------------------")

    IO.outputStr("Provide a list of maneuvers that will keep the satellite in contact with our terraforming station on mars")
    IO.outputStr("If your manuevers are valid you can view the trajectory at {}:{}".format(service_host, service_port) )
    IO.outputStr("You can manuever as many times as you want but you only have {} km/s of ∆V".format( dv_limit))
    IO.outputStr("Maneuver Times is in Gregorian UTC:  YYYY-MM-DD HH:MM:SS.sss")
    IO.outputStr("Manuevers are in Mars Centered Intertial Coordinate system")
    
    IO.outputStr("Input your manuevers in the following format: ")
    IO.outputStr("Time,∆Vx,∆Vy,∆VZ")

    IO.outputStr("Enter 'DONE' when you want have added all your maneuvers")

    keep_going = True 
    while( keep_going ):
        entry = IO.input_str( "Input next maneuver: ")
        entry = entry.replace("\n","")
        if( "DONE" == entry  ):
            keep_going = False
        else:
            gmat_template.add_maneuver( entry )
    # Check that we have enough delta v for the mission
    total_dv = gmat_template.get_total_dv()
    if( total_dv > dv_limit ):
        IO.outputStr("Incorrect")
        IO.outputStr("We dont have the fuel to do these maneuvers")
        return False
    valid_times = gmat_template.validate_order()
    if( False == valid_times  ):
        IO.outputStr("Maneuver times must be after the epoch and be given in order")
        return False
    
    script_name = "./gmat_scripts/mission.script"
    gmat_template.render( template_directory="./gmat_scripts" , template_filename="gmat_template.script" ,  out_path=script_name)

    IO.outputStr("Calculating..... (this may take a few seconds) ")
    
    gmat_exe.run_script( script_name )
    IO.outputStr("Checking your trajectory.... (this may also take a few seconds)" )
    satellite_mars_fixed= gmat_exe.get_log('sat_mars_fixed.txt')
    satellite_mars_inertial= gmat_exe.get_log('sat_mars_inertial.txt')
    satellite_gs   = gmat_exe.get_log('sat_terraformer.txt')

    try: 
        mars_ok = check_proximity( data=satellite_mars_inertial , min_proximity=MarsRadius , loc="Mars" , snark="You crashed into Mars. I hope you didnt hit the terraforming equipment")
        mars_system_ok = check_proximity( data=satellite_mars_inertial , max_proximity=MarsSystem , loc="Mars" , from_date=communication_start_date,  snark="You got too far away from Mars.")
        in_range_ok = check_proximity( data=satellite_gs , max_proximity=TerraformerRange , loc="Mars" , from_date=communication_start_date,  snark="The satellite isnt in range of the ground transmitter") 
        elevation_ok = check_axis_value( data=satellite_gs , axis="X" , min=0 , max=np.Inf , from_date=communication_start_date , snark="The communication satellite is below the horizon. Now if the Aliens attack we wont know about it." )
        result = mars_ok and mars_system_ok and in_range_ok and elevation_ok
    except OrbitError:
        result = False
        # Make template
    booster_czml = cesium.CesiumOrbitTemplate()
    booster_czml.add_groundstation("Terraformer", latitude, longitude, altitude )
    booster_czml.set_orbit( satellite_mars_fixed,satellite_mars_fixed , decimation=3)
    booster_czml.set_window( start_date, stop_date ) 
    booster_czml.render( template_directory="viewer/czml", template_filename="satellite.template", out_path="viewer/czml/satellite.czml", name="CommsSat")
    

    
    
    return result

def check_time_value( time , value, min=np.Inf, max=np.Inf , from_date=datetime(year=1, month=1,day=1) , to_date=datetime(year=4000,month=1,day=1) ):
    time_str = time.strftime("%Y %b %D %H:%m:%S.%f ")
    from_date = from_date.replace( tzinfo=timezone.utc)
    to_date = to_date.replace( tzinfo=timezone.utc)
    dt1 = time - from_date
    dt2 = time - to_date
    if( (dt1.total_seconds() > 0 ) and (dt2.total_seconds()<0)):
        if value < min:
            raise LowOutOfBounds
        if value > max:
            raise HighOutOfBounds 
    else:
        pass
    return True 
def check_axis_value( data , axis, min=-np.Inf , max=np.Inf , from_date=datetime(year=1, month=1,day=1) , to_date=datetime(year=4000,month=1,day=1),  loc="" , snark ="" ):
    for item in data:
        time = item["time"]
        value = item[axis]
        try:
            ok = check_time_value( time ,value , min=min , max=max, from_date=from_date , to_date=to_date)
        except LowOutOfBounds:
            IO.outputStr(snark)
            raise OrbitError
        except HighOutOfBounds:
            IO.outputStr(snark) 
            raise OrbitError
        except:
            IO.outputStr("Unexpected error - see admin")
            raise OrbitError
    return True
def check_proximity( data , min_proximity=-np.Inf , max_proximity=np.Inf , from_date=datetime(year=1, month=1,day=1) , to_date=datetime(year=4000,month=1,day=1),  loc="" , snark ="" ):
    for item in data:

        time = item["time"]
        position = np.array( [ item["X"], item["Y"], item["Z"]])
        d_to_center =  np.linalg.norm( position )
        ok = False
        time_str = time.strftime("%Y %b %D %H:%m:%S.%f ")

        try:
            ok = check_time_value( time , d_to_center  , min=min_proximity, max=max_proximity , from_date=from_date , to_date=to_date)
        except HighOutOfBounds:
            IO.outputStr("Proximity alarm - you got too far from {} at {}".format(loc, time_str))
            IO.outputStr(snark)
            raise OrbitError
        except LowOutOfBounds:
            IO.outputStr("Proximity alarm - you got to close to {} at {}".format(loc,time_str))
            IO.outputStr(snark)
            raise OrbitError
        except:
            IO.outputStr("Unexpected error - see admin")
            raise OrbitError
    return True
def game_over():
    f = open("game_over.txt")
    lines  = f.readlines()
    for line in lines:
        IO.outputStr( line )
    f.close()



if __name__ == "__main__":
    try:
        c = CHALLENGE.Challenge( )
        flag = c.getFlag()
        result = challenge()

        

        if( True == result ):
            IO.outputStr("Complete!")
            IO.outputStr("Flag: {}".format(  flag ) )
        else:
            IO.outputStr("Bye.")
    finally:
        IO.outputStr(f"Viewer will show data in the Mars Centered Mars Fixed Frame at http://{c.getHost()}:{c.getPort()}")
        IO.outputStr("Quitting")
    sys.exit(0)
