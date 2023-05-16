
import os
import numpy as np
import rotation
import scipy.constants
# import general simulation support files
from Basilisk.utilities import SimulationBaseClass
from Basilisk.utilities import unitTestSupport  # general support file with common unit test functions
import matplotlib.pyplot as plt
from Basilisk.utilities import macros
from Basilisk.utilities import orbitalMotion

# import simulation related support
from Basilisk.simulation import spacecraft
from Basilisk.simulation import extForceTorque
from Basilisk.utilities import simIncludeGravBody
from Basilisk.simulation import simpleNav
from Basilisk.simulation import GravityGradientEffector


# import message declarations
from Basilisk.architecture import messaging


# The path to the location of Basilisk
# Used to get the location of supporting data.
from Basilisk import __path__
bskPath = __path__[0]
fileName = os.path.basename(os.path.splitext(__file__)[0])


class GravSat:
    def __init__(self, axis , inertia ):
        simTaskName = "PhysicsTask"
        simProcessName = "PhysicsProcess"
        self.axisBody = axis 
        scSim = SimulationBaseClass.SimBaseClass()
        samplingTime = int(1000 * 1.0e9) # Ns 
        
        #
        #  create the simulation process
        #
        dynProcess = scSim.CreateNewProcess(simProcessName)

        # create the dynamics task and specify the integration update time
        simulationTimeStep = macros.sec2nano(100)
        dynProcess.addTask(scSim.CreateNewTask(simTaskName, simulationTimeStep))
        # initialize spacecraft object and set properties
        scObject = spacecraft.Spacecraft()
        scObject.ModelTag = "spacecraftBody"
        # define the simulation inertia
        scObject.hub.mHub = 750.0  # kg - spacecraft mass
        scObject.hub.r_BcB_B = [[0.0], [0.0], [0.0]]  # m - position vector of body-fixed point B relative to CM
        i_flat = inertia.flatten() 
        scObject.hub.IHubPntBc_B = unitTestSupport.np2EigenMatrix3d( i_flat )

        # add spacecraft object to the simulation process
        scSim.AddModelToTask(simTaskName, scObject)

        # clear prior gravitational body and SPICE setup definitions
        gravFactory = simIncludeGravBody.gravBodyFactory()

        # setup Earth Gravity Body
        earth = gravFactory.createEarth()
        earth.isCentralBody = True  # ensure this is the central gravitational body
        mu = earth.mu

        # attach gravity model to spacecraft
        scObject.gravField.gravBodies = spacecraft.GravBodyVector(list(gravFactory.gravBodies.values()))

        # Attach gravity gradient model to the sapcecraft 
        ggEff = GravityGradientEffector.GravityGradientEffector()
        ggEff.ModelTag = "GG"
        ggEff.addPlanetName(earth.planetName)
        scObject.addDynamicEffector(ggEff)
        scSim.AddModelToTask(simTaskName, ggEff)
        self.ggLog = ggEff.gravityGradientOutMsg.recorder(samplingTime)
        scSim.AddModelToTask(simTaskName, self.ggLog)

        #   initialize Spacecraft States with initialization variables
        #
        # setup the orbit using classical orbit elements
        oe = orbitalMotion.ClassicElements()
        oe.a = 42164.0e3  # meters
        oe.e = 0.0
        oe.i = 0 * macros.D2R
        oe.Omega = 0 * macros.D2R
        oe.omega = 0 * macros.D2R
        oe.f = 0 * macros.D2R
        rN, vN = orbitalMotion.elem2rv(mu, oe)
        scObject.hub.r_CN_NInit = rN  # m   - r_CN_N
        scObject.hub.v_CN_NInit = vN  # m/s - v_CN_N
        # Calculate orietation

        #
        
        nadir = -rN
    
        q = rotation.axisToQuat( axis , nadir )
        dcm = rotation.quatToDcm( q )
        mrp = rotation.quatToMrp( q )
        scObject.hub.sigma_BNInit = [[mrp[0]], [mrp[1]], [mrp[2]]]  # sigma_BN_B
        N =  np.sqrt( mu / np.power( oe.a , 3))
        disturbance = 0.000001
        w_e = np.array( [ 0 , 0 , N+disturbance ])
        
        w_b  = np.matmul( dcm , w_e) 
        
        scObject.hub.omega_BN_BInit = [[w_b[0]], [w_b[1]], [w_b[2]]]  # rad/s - omega_BN_B

        # Add statelog
        self.stateLog = scObject.scStateOutMsg.recorder(samplingTime)
        scSim.AddModelToTask( simTaskName , self.stateLog )
        self.sim = scSim
        self.Period = np.sqrt( np.power( oe.a , 3 ) / (mu /( 4*np.pi*np.pi)) )
    def run( self , nOrbits  ):

        stopTimeNanoSecs = nOrbits * self.Period * 1.0e9
        self.sim.InitializeSimulation()
        self.sim.ConfigureStopTime( stopTimeNanoSecs )
        #self.sim.SetProgressBar(True)
        self.sim.ExecuteSimulation()

        mrp = self.stateLog.sigma_BN
        pos = self.stateLog.r_BN_N 
        w  = self.stateLog.omega_BN_B
        mrp = self.stateLog.sigma_BN 
        ggTorque = self.ggLog.gravityGradientTorque_B
        thrs = self.stateLog.times() / ( 3600 * 1.0e9 )
        # Loop over all time steps
        angles = []
        for m,r in zip( mrp , pos ):
            nadirEci = -r
            q = rotation.MrpToQuaternion( m )
            angle = rotation.angleDifference( self.axisBody , nadirEci , q)
            angles.append(  angle)
        return thrs,angles,mrp
