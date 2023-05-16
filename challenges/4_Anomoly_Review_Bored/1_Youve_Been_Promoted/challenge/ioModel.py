
import sys
from Basilisk.utilities import simulationArchTypes, macros
from Basilisk.architecture import messaging
import numpy as np
import ctf.io

class ActuatorInput(simulationArchTypes.PythonModelClass):
    def __init__(self, priority, maxTorque, maxDipole):
        super(ActuatorInput, self).__init__(f"ActuatorInput", True, priority)
        # 
        self.wheelsCmds = messaging.ArrayMotorTorqueMsg()
        self.dipoleCmds = messaging.MTBCmdMsg()
        #
        self.MaxT = maxTorque
        self.MaxD = maxDipole
        # Some intro information
        ctf.io.outputStr("Reaction wheels accept torque commands in N-m")
        ctf.io.outputStr(f"Reaction wheel commands are valid between [-{maxTorque}, {maxTorque}] N-m")
        ctf.io.outputStr("Available reaction wheels:")
        ctf.io.outputStr("- Wheel_X: aligned with body X axis")
        ctf.io.outputStr("- Wheel_Y: aligned with body Y axis")
        ctf.io.outputStr("- Wheel_Z: aligned with body Z axis")
        ctf.io.outputStr("")
        ctf.io.outputStr("Magnetic Torquer Bars (MTB) accept commands in magnetic dipole (A-m^2)")
        ctf.io.outputStr(f"MTB dipole commands are valid between [-{maxDipole}, {maxDipole}] (A-m^2)")
        ctf.io.outputStr("Available MTB")
        ctf.io.outputStr("- MTB_X: aligned with body X axis")
        ctf.io.outputStr("- MTB_Y: aligned with body Y axis")
        ctf.io.outputStr("- MTB_Z: aligned with body Z axis")
        ctf.io.outputStr("")
        ctf.io.outputStr("Actuator commands are formatted as: ")
        ctf.io.outputStr("Wheel_X, Wheel_Y, Wheel_Z, MTB_X, MTB_Y, MTB_Z")
        ctf.io.outputStr("")

    def updateState(self, currentTime):
        try:
            data = ctf.io.input_number_array("Enter actuator command:" , 6 )
            
        except:
            print("Exiting.")
            sys.exit()
        
        wheelCmd = data[0:3]
        dipoleCmds = data[3:6]
        # Do some limiting here to stop weirdness
        wheelCmd = np.clip( wheelCmd , -self.MaxT,self.MaxT  )
        dipoleCmds = np.clip( dipoleCmds, -self.MaxD, self.MaxD )
        # Send wheel
        wheelPayload = messaging.ArrayMotorTorqueMsgPayload()
        wheelPayload.motorTorque = wheelCmd
        self.wheelsCmds.write(wheelPayload , currentTime, self.moduleID)

        # Send dipole
        dipolePayload =  messaging.MTBCmdMsgPayload()
        dipolePayload.mtbDipoleCmds = dipoleCmds 
        self.dipoleCmds.write(dipolePayload , currentTime, self.moduleID)

class SensorOutput(simulationArchTypes.PythonModelClass):
    def __init__(self,  priority):
        super(SensorOutput, self).__init__(f"SensorOutput", True, priority)
        # 
        self.wheelSpeedsMsg = messaging.RWSpeedMsgReader()
        self.stateMsg = messaging.SCStatesMsgReader()
        self.magMsg =  messaging.TAMSensorMsgReader()
        self.mtbTorqueMsg   = messaging.MTBMsgReader()

    def getWheel( self ):
        return self.wheelSpeed
    def getW( self ):
        return self.angV
    def updateState(self, currentTime):
        
        state = self.stateMsg()
        wheelSpeed = self.wheelSpeedsMsg().wheelSpeeds[0:3]
        self.wheelSpeed = wheelSpeed
        
        angV = state.omega_BN_B
        self.angV = angV
        #magTorqueAchieved = self.mtbTorqueMsg().mtbNetTorque_B
        magField = self.magMsg().tam_S
        outVec = np.hstack((currentTime/1.0e9, angV,wheelSpeed,magField )).ravel()
        outStr = ",".join( outVec.astype( str ))
        ctf.io.outputStr("Sensor:Time (sec), AngV_X (rad/s), AngV_Y (rad/s)), AngV_Z(rad/s), WheelX(rad/s), WheelY(rad/s), WheelZ(rad/s), magX (T), magY(T), magZ(T)")
        ctf.io.outputStr( outStr )
