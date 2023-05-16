"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
from gnuradio import gr


class blk(gr.sync_block):  # other base classes are basic_block, decim_block, interp_block
    """Embedded Python Block example - a simple multiply const"""

    def __init__(self,
            symbol_map = [],
            constellation_points = [],
            tolerance = 1):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='QAM Slicer',   # will show up in GRC
            in_sig=[np.complex64],
            out_sig=[np.byte]
        )
        # if an attribute with the same name as a parameter is found,
        # a callback is registered (properties work, too).
        self.tolSq = tolerance ** 2
        self.map = {constellation_points[i]: symbol_map[i] for i in range(len(constellation_points))}
        self.const = constellation_points
        self.log = gr.logger(self.alias())
        self.log.debug("QAM Slicer initialized")

    def work(self, input_items, output_items):
        i=0
        for s in input_items[0]:
            for sym in self.const:
                c = s - sym
                rSq = c.real ** 2 + c.imag ** 2
                if rSq < self.tolSq:
                    output_items[0][i] = self.map[sym]
                    break 
            i += 1
        return len(output_items[0])
