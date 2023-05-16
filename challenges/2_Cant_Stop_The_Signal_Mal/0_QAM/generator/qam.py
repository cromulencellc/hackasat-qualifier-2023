#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: qam
# Author: cromulence
# GNU Radio version: 3.10.1.1

from gnuradio import analog
from gnuradio import blocks
import pmt
from gnuradio import digital
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation




class qam(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "qam", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.bps = bps = 4
        self.bitrate = bitrate = 9600
        self.samp_rate = samp_rate = bitrate/bps

        ##################################################
        # Blocks
        ##################################################
        self.digital_map_bb_0_0 = digital.map_bb([0,1,2,3])
        self.digital_map_bb_0 = digital.map_bb([0,1,2,3])
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate,True)
        self.blocks_stream_demux_0 = blocks.stream_demux(gr.sizeof_char*1, (1, 1))
        self.blocks_repack_bits_bb_0 = blocks.repack_bits_bb(8, 2, "", False, gr.GR_MSB_FIRST)
        self.blocks_head_0 = blocks.head(gr.sizeof_char*1, 1024)
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, 'flag', True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, 'symbols', False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.blocks_char_to_float_0_0 = blocks.char_to_float(1, .5)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 0.5)
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.blocks_add_const_vxx_0_0 = blocks.add_const_ff(-3)
        self.blocks_add_const_vxx_0 = blocks.add_const_ff(-3)
        self.analog_noise_source_x_0 = analog.noise_source_c(analog.GR_GAUSSIAN, 0.05, 0)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_noise_source_x_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_add_const_vxx_0_0, 0), (self.blocks_float_to_complex_0, 1))
        self.connect((self.blocks_add_xx_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.blocks_char_to_float_0_0, 0), (self.blocks_add_const_vxx_0_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_head_0, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_head_0, 0), (self.blocks_repack_bits_bb_0, 0))
        self.connect((self.blocks_repack_bits_bb_0, 0), (self.blocks_stream_demux_0, 0))
        self.connect((self.blocks_stream_demux_0, 0), (self.digital_map_bb_0, 0))
        self.connect((self.blocks_stream_demux_0, 1), (self.digital_map_bb_0_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.digital_map_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.digital_map_bb_0_0, 0), (self.blocks_char_to_float_0_0, 0))


    def get_bps(self):
        return self.bps

    def set_bps(self, bps):
        self.bps = bps
        self.set_samp_rate(self.bitrate/self.bps)

    def get_bitrate(self):
        return self.bitrate

    def set_bitrate(self, bitrate):
        self.bitrate = bitrate
        self.set_samp_rate(self.bitrate/self.bps)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_throttle_0.set_sample_rate(self.samp_rate)




def main(top_block_cls=qam, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    tb.wait()


if __name__ == '__main__':
    main()
