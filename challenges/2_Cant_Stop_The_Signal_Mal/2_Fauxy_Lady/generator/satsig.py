#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: satsig
# Author: cromulence
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
import math
import pmt
from gnuradio import channels
from gnuradio.filter import firdes
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation




class satsig(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "satsig", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.sps = sps = 4
        self.samp_rate = samp_rate = int(64e3)
        self.bitrate = bitrate = 1200
        self.rep = rep = 1
        self.pkt_len = pkt_len = 100
        self.interp_des = interp_des = samp_rate/sps/bitrate
        self.constellation = constellation = digital.constellation_bpsk().base()
        self.audio_rate = audio_rate = int(44.1e3)

        ##################################################
        # Blocks
        ##################################################
        self.rational_resampler_xxx_0_0 = filter.rational_resampler_ccc(
                interpolation=int(audio_rate/100),
                decimation=int(samp_rate/100),
                taps=[],
                fractional_bw=0)
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=int(samp_rate/100),
                decimation=int(bitrate*sps/100),
                taps=[],
                fractional_bw=0)
        self.low_pass_filter_0 = filter.fir_filter_ccf(
            1,
            firdes.low_pass(
                0.3,
                samp_rate,
                1.5e3,
                1.5e2,
                window.WIN_HAMMING,
                6.76))
        self.digital_constellation_modulator_0 = digital.generic_mod(
            constellation=constellation,
            differential=True,
            samples_per_symbol=sps,
            pre_diff_code=True,
            excess_bw=0.35,
            verbose=False,
            log=False,
            truncate=False)
        self.channels_channel_model_0 = channels.channel_model(
            noise_voltage=.01,
            frequency_offset=0.0,
            epsilon=1.0,
            taps=[1.0 + 1.0j],
            noise_seed=0,
            block_tags=False)
        self.blocks_wavfile_sink_0 = blocks.wavfile_sink(
            'signal.wav',
            2,
            audio_rate,
            blocks.FORMAT_WAV,
            blocks.FORMAT_FLOAT,
            False
            )
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, audio_rate,True)
        self.blocks_freqshift_cc_0 = blocks.rotator_cc(2.0*math.pi*1e3/samp_rate)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, 'tx_stream', False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.intern("flag"))
        self.blocks_complex_to_float_0 = blocks.complex_to_float(1)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_complex_to_float_0, 0), (self.blocks_wavfile_sink_0, 0))
        self.connect((self.blocks_complex_to_float_0, 1), (self.blocks_wavfile_sink_0, 1))
        self.connect((self.blocks_file_source_0, 0), (self.digital_constellation_modulator_0, 0))
        self.connect((self.blocks_freqshift_cc_0, 0), (self.rational_resampler_xxx_0_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_complex_to_float_0, 0))
        self.connect((self.channels_channel_model_0, 0), (self.blocks_freqshift_cc_0, 0))
        self.connect((self.digital_constellation_modulator_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.channels_channel_model_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.rational_resampler_xxx_0_0, 0), (self.blocks_throttle_0, 0))


    def get_sps(self):
        return self.sps

    def set_sps(self, sps):
        self.sps = sps
        self.set_interp_des(self.samp_rate/self.sps/self.bitrate)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_interp_des(self.samp_rate/self.sps/self.bitrate)
        self.blocks_freqshift_cc_0.set_phase_inc(2.0*math.pi*1e3/self.samp_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(0.3, self.samp_rate, 1.5e3, 1.5e2, window.WIN_HAMMING, 6.76))
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(1, self.samp_rate, 1e3, 1e2, window.WIN_HAMMING, 6.76))
        self.low_pass_filter_0_0_0.set_taps(firdes.low_pass(1, self.samp_rate, 15e3, 1e3, window.WIN_HAMMING, 6.76))
        self.low_pass_filter_0_0_0_0.set_taps(firdes.low_pass(0.5, self.samp_rate, self.samp_rate/2, 5e3, window.WIN_HAMMING, 6.76))

    def get_bitrate(self):
        return self.bitrate

    def set_bitrate(self, bitrate):
        self.bitrate = bitrate
        self.set_interp_des(self.samp_rate/self.sps/self.bitrate)

    def get_rep(self):
        return self.rep

    def set_rep(self, rep):
        self.rep = rep

    def get_pkt_len(self):
        return self.pkt_len

    def set_pkt_len(self, pkt_len):
        self.pkt_len = pkt_len

    def get_interp_des(self):
        return self.interp_des

    def set_interp_des(self, interp_des):
        self.interp_des = interp_des

    def get_constellation(self):
        return self.constellation

    def set_constellation(self, constellation):
        self.constellation = constellation

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.blocks_throttle_0.set_sample_rate(self.audio_rate)




def main(top_block_cls=satsig, options=None):
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
