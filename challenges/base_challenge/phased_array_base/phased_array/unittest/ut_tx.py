import sys
from unittest import TestCase
from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
import scipy.constants


class CarrierTransmitter(gr.hier_block2):
    def __init__(self, Fs , Fc, N):
        gr.hier_block2.__init__(
            self, "Carrier TX",
                gr.io_signature(0, 0, 0),
                gr.io_signature(1, 1, gr.sizeof_gr_complex*1)
        )

        ##################################################
        # Variables
        ##################################################
        
        print(f"Size: {gr.sizeof_gr_complex}")
        ##################################################
        # Blocks
        ##################################################
        self.amplitude  = blocks.vector_source_c(N * [ 1 ] , False, 1, [])
        self.freq_shift = blocks.rotator_cc(2.0*scipy.constants.pi*Fc/Fs)
    
        ##################################################
        # Connections
        ##################################################
        self.connect( (self.amplitude,0), (self.freq_shift,0))
        self.connect( ( self.freq_shift , 0 ) , (self,0))
