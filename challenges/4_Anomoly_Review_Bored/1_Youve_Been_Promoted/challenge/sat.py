class Satellite:
    def __init__( self ):
        self.max_wheel_torque = 0.2
        self.wheels = [ {"axis":[1.0,0.0,0.0], "type":"Honeywell_HR16", "base_power":10.0, "efficiency":.5, "max_momentum":50.0, "init":.5},
                        {"axis":[0.0,1.0,0.0], "type":"Honeywell_HR16", "base_power":10.0, "efficiency":.5, "max_momentum":50.0, "init":-.75},
                        {"axis":[0.0,0.0,1.0], "type":"Honeywell_HR16", "base_power":10.0, "efficiency":.5, "max_momentum":50.0, "init":0.45}
                      ]
        self.mtb_max_dipole = 1000.0
        self.mtb = [ {"axis":[1.0,0.0,0.0] },#??
                            {"axis":[0.0,1.0,0.0] },
                            {"axis":[0.0,0.0,1.0] },
                        ]
        
        self.inertia = [200.0, 0., 0.,
                        0., 200.0, 0.,
                        0., 0., 200.0 ] # 
        self.mass = 100.0

        self.w0 =[0.1,0.1,-0.2] #*[.04,.05,-.01]        
        self.i = 75.0
        self.a = 6378+500