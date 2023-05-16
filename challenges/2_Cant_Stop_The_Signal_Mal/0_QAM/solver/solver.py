#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: qam solver
# Author: cromulence
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
import pmt
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import solver_epy_block_0 as epy_block_0  # embedded python block




class solver(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "qam solver", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.bps = bps = 4
        self.bitrate = bitrate = 9600
        self.samp_rate = samp_rate = bitrate/bps

        ##################################################
        # Blocks
        ##################################################
        self.epy_block_0 = epy_block_0.blk(symbol_map=[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF], constellation_points= [(-3-3j), (-3-1j), (-3+1j), (-3+3j), (-1-3j), (-1-1j), (-1+1j), (-1+3j), (1-3j), (1-1j), (1+1j), (1+3j), (3-3j), (3-1j), (3+1j), (3+3j)], tolerance=1)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate,True)
        self.blocks_repack_bits_bb_0 = blocks.repack_bits_bb(4, 8, "", False, gr.GR_MSB_FIRST)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, '../out/symbols', False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, 'decoded', False)
        self.blocks_file_sink_0.set_unbuffered(False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_repack_bits_bb_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.epy_block_0, 0))
        self.connect((self.epy_block_0, 0), (self.blocks_repack_bits_bb_0, 0))


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




def main(top_block_cls=solver, options=None):
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
