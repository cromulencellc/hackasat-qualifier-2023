
import re
import os
import pexpect
import numpy as np
def demote(user_uid, user_gid):
    def set_ids():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return set_ids
def unpackLine( line ):
    line = line.replace("Estimated ", "")
    data = re.split(',|:', line)
    x = float(data[1])
    y = float(data[2])
    z = float(data[3])
    d = {
        "time": data[0],
        "Pos": np.array([x,y,z])
    }
    if not np.isfinite( d["Pos"]).all():
        print("Woah the filter is spitting out non-finite values", flush=True)
        raise ValueError
    return d
def unpack_matrix( lines ):
    confStr = (" ".join(lines)).split()
    confVec =  [float(x) for x in confStr]

    if not np.isfinite( confVec ).all():
        print("Woah the filter is spitting out non-finite covariances", flush=True)
        raise ValueError
    return np.array( confVec).reshape( 3,3)
class FilterBinary:
    def getLastPosition( self ):
        return self.positions[-1]["Pos"]
    def getCovariance( self ):
        return self.confMat
    def getNumEstimates(self):
        return len(self.positions)
    
    def run(self):
        #proc = subprocess.Popen(["./src/build/Kalman"],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        child = pexpect.spawn( "./Kalman")
        outArray = []
        keepGoing = True
        while( True == keepGoing ):
            child.expect( ">")
            out = child.before.decode()
            outLines = out.split("\n")
            outLines[-1] = outLines[-1]+">"
            for line in outLines:
                if line.startswith("Estimated"):
                    o = unpackLine( line )
                    outArray.append( o )
                    pass
                elif "Complete" in line:
                    keepGoing = False
                else:
                    pass
                print( line )
            if True == keepGoing:
                inputTxt = input()
                child.sendline( inputTxt )
            #else:
            #    pass
        child.expect("Filter Exit")
        conflines = child.before.decode().split("\r\n")
        
        self.confMat = unpack_matrix( conflines[2:5])
        print("Final position error covariance:")
        print( self.confMat , flush=True)
        self.positions = outArray
