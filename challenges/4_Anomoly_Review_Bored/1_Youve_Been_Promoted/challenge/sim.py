

import numpy as np
import os
from sat import Satellite
import ioModel
import ctf.io as o
from Basilisk.fswAlgorithms import (mrpFeedback, attTrackingError,
                                    inertial3D, rwMotorTorque,
                                    tamComm, mtbMomentumManagement)
from Basilisk.simulation import (reactionWheelStateEffector, 
                                 simpleNav,
                                 magneticFieldWMM, magnetometer, MtbEffector,
                                 spacecraft)
from Basilisk.utilities import (SimulationBaseClass, fswSetupRW, macros,
                                orbitalMotion, simIncludeGravBody,
                                simIncludeRW, unitTestSupport, vizSupport)
from Basilisk.architecture import messaging
import datetime 
# The path to the location of Basilisk
# Used to get the location of supporting data.
from Basilisk import __path__
bskPath = __path__[0]
spiceTimeFormat = "%Y %B %-d, %-H:%-M:%S.%f (UTC)"


fileName = os.path.basename(os.path.splitext(__file__)[0])


class Simulator:
    def __init__( self ):
        self.config = Satellite()
        self.epoch = datetime.datetime( 2022,1,1,0,0,0)

        self.configure()
    def run( self , seconds ):
        self.sim.ConfigureStopTime( seconds * 1.0e9 )
        self.sim.InitializeSimulation()
        #self.sim.ShowExecutionOrder() # Remove me
        #self.sim.showProgressBar = True 
        self.sim.ExecuteSimulation()
    def grade( self , wLimit, wheelLimit ):
        w = self.sensor.getW()
        wheels = self.sensor.getWheel()
        magW = np.linalg.norm( w )
        okCount = 0 
        if magW < wLimit:
            o.outputStr("Angular Velcocity: OK")
            okCount += 1
        else:
            o.outputStr("Angular Velcocity: BAD")

        for k in range( 0 , len(wheels)):
            if np.abs(wheels[k]) < wheelLimit:
                o.outputStr(f"Wheel {k}: OK")
                okCount += 1
            else:
                o.outputStr(f"Wheel {k}: BAD")
        return okCount == 4

    def configure( self ):
        # Create simulation variable names
        self.physicsTaskName = "simCppTask"
        self.physicsProcessName = "DynamicsProcess"
        self.ioProcessName = "ioProcess"
        self.ioTaskName = "ioTaskName"
        #  Create a sim module as an empty container
        self.sim = SimulationBaseClass.SimBaseClass()
        

        ## Handle tasks and processes
        simulationTimeStep = macros.sec2nano(1.0)
        # Process creation
        dynamicsProcess = self.sim.CreateNewProcess(self.physicsProcessName, priority=20)
        self.ioProcess  = self.sim.CreateNewPythonProcess(self.ioProcessName , priority=10 )

        # Task creation
        dynamicsTask = self.sim.CreateNewTask(self.physicsTaskName, simulationTimeStep)
        self.ioProcess.createPythonTask(self.ioTaskName, simulationTimeStep, True, 100)


        # Task->Processing map
        dynamicsProcess.addTask( dynamicsTask )

    #
    #   setup the simulation tasks/objects
    #
        self.sc = spacecraft.Spacecraft()
        self.sc.ModelTag = "chal-sat"
        self.sim.AddModelToTask(self.physicsTaskName, self.sc, None, 1)

        self.add_environment()
        self.addTAM()
        self.add_mag_torque_bar()
        self.add_wheels()
        self.add_io()
        self.initconds()
    def initconds( self ):
        oe = orbitalMotion.ClassicElements()
        oe.a = self.config.a * 1000.0 # Basilisk needs this in meters
        oe.e = 0
        oe.i = self.config.i * macros.D2R
        oe.Omega =0.0
        oe.omega = 1.0 
        oe.f = 0
        mu = 3.986004418e14 # Hard coded to earth
        rN, vN = orbitalMotion.elem2rv(mu, oe )

        self.sc.hub.r_CN_NInit = rN
        self.sc.hub.v_CN_NInit = vN
        
        rodrigues = [0,0,0]
        self.sc.hub.sigma_BNInit = [[rodrigues[0]], [rodrigues[1]], [rodrigues[2]]]  # sigma_BN_B
        self.sc.hub.omega_BN_BInit = [[self.config.w0[0]],[self.config.w0[1]], [self.config.w0[2]]]
        self.sc.hub.mHub = self.config.mass  # kg - spacecraft mass
        self.sc.hub.r_BcB_B = [[0.0], [0.0], [0.0]]  # m - position vector of body-fixed point B relative to CM

        inertiaTensor = self.config.inertia
        self.sc.hub.IHubPntBc_B = unitTestSupport.np2EigenMatrix3d(inertiaTensor)

    def add_io( self ):
        self.sensor = ioModel.SensorOutput(200)
        self.actuator = ioModel.ActuatorInput(10 , self.config.max_wheel_torque , self.config.mtb_max_dipole)
        self.ioProcess.addModelToTask( self.ioTaskName , self.sensor )
        self.ioProcess.addModelToTask( self.ioTaskName , self.actuator )
        # actuator out
        self.rwStateEffector.rwMotorCmdInMsg.subscribeTo( self.actuator.wheelsCmds )
        self.mtbEff.mtbCmdInMsg.subscribeTo( self.actuator.dipoleCmds )
        # sensor in
        self.sensor.magMsg.subscribeTo( self.mag.tamDataOutMsg )
        self.sensor.stateMsg.subscribeTo( self.sc.scStateOutMsg)
        self.sensor.wheelSpeedsMsg.subscribeTo( self.rwStateEffector.rwSpeedOutMsg)
        self.sensor.mtbTorqueMsg.subscribeTo( self.mtbEff.mtbOutMsg )
    def add_environment( self ):
        # M
        self.magField = magneticFieldWMM.MagneticFieldWMM()
        self.magField.ModelTag = f"WMM"
        self.magField.dataPath = bskPath + '/supportData/MagneticField/'
        timeStr = self.epoch.strftime(spiceTimeFormat)
        self.epochMsg = unitTestSupport.timeStringToGregorianUTCMsg(timeStr)
        self.magField.epochInMsg.subscribeTo(self.epochMsg)
        self.magField.addSpacecraftToModel(self.sc.scStateOutMsg)  # this command can be repeated if multiple
        self.sim.AddModelToTask(self.physicsTaskName, self.magField)
        # G
        gravFactory = simIncludeGravBody.gravBodyFactory()

        # setup Earth Gravity Body
        earth = gravFactory.createEarth()
        earth.isCentralBody = True  # ensure this is the central gravitational body
        mu = earth.mu
        self.sc.gravField.gravBodies = spacecraft.GravBodyVector(list(gravFactory.gravBodies.values()))
    def addTAM( self ):
         # create the minimal TAM module
        self.mag = magnetometer.Magnetometer()
        self.mag.ModelTag = f"mag_sensor"
        # specify the optional TAM variables
        self.mag.scaleFactor = 1
        self.mag.senNoiseStd = [ 0 for k in range(3)]
        # The author of the magnetometer model used euler angles (the only possible reason for this is they hate us)
        # so we have to do this conversion
        # Since we are doing this lets get our assumptions straight
        # - an intrinsic Z->Y->X rotation
        # - coordinates are column vectors
        # - coordinate systems are right handed 
        # - rotation about Z axis is "yaw"
        # - rotation about the Y axis is "pitch"
        # - rotation about the X axis is "roll"
        # - euler angles are ambiguous and we dislike them
        # yuck - euler angles...im going to go wash my hands
        self.mag.setBodyToSensorDCM( yaw=0, pitch=0, roll=0)
        # Task
        self.sim.AddModelToTask(self.physicsTaskName, self.mag)

        self.mag.stateInMsg.subscribeTo( self.sc.scStateOutMsg)
        self.mag.magInMsg.subscribeTo(  self.magField.envOutMsgs[0] )

    def add_mag_torque_bar( self ):
        self.mtbEff = MtbEffector.MtbEffector()
        self.mtbEff.ModelTag = "MtbEff"
        self.sc.addDynamicEffector(self.mtbEff)
        # row major toque bar alignments
        nMtb = len(self.config.mtb)
        mtbConfigParams = messaging.MTBArrayConfigMsgPayload()
        mtbConfigParams.numMTB = nMtb
        k=0
        dipoleLimit = []
        Gt_B = [0.0]*3*nMtb
        for mtb in  self.config.mtb:
            dipoleLimit.append( self.config.mtb_max_dipole )
            for z in range(3):
                Gt_B[k +z*nMtb] = mtb["axis"][z] 
            k+=1
            
        mtbConfigParams.GtMatrix_B = Gt_B
        self.mtbLen = nMtb     
        
        mtbConfigParams.maxMtbDipoles = dipoleLimit
        self.mtbParamsInMsg = messaging.MTBArrayConfigMsg().write(mtbConfigParams)
        # Tasks 
        self.sim.AddModelToTask(self.physicsTaskName, self.mtbEff)
        # Message subscriptions 
        self.mtbEff.mtbParamsInMsg.subscribeTo(self.mtbParamsInMsg)
        self.mtbEff.magInMsg.subscribeTo( self.magField.envOutMsgs[0])
        
    def add_wheels( self):        
        # Add the state effector
        self.rwFactory = simIncludeRW.rwFactory()

        self.rwStateEffector =  reactionWheelStateEffector.ReactionWheelStateEffector()
        self.wheels = []
        for wheel in self.config.wheels:
            
            rWheel = self.rwFactory.create( wheel["type"], wheel["axis"], maxMomentum=wheel["max_momentum"], Omega=0.0 
                           , RWModel= messaging.BalancedWheels )
            rWheel.Omega = wheel["init"] * rWheel.Omega_max
            rWheel.OmegaBefore = rWheel.Omega
            self.wheels.append( rWheel )
        self.rwFactory.addToSpacecraft(f"WheelEffector", self.rwStateEffector, self.sc)
        self.sim.AddModelToTask( self.physicsTaskName , self.rwStateEffector)


