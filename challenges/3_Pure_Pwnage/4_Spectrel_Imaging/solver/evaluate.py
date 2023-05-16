import re
import numpy as np
from constants import *
import struct 
import bz2
import argparse
import matplotlib.pyplot as plt 
import matplotlib.colors as C
class StatAnalyzer:
    def __init__( self , fileIn ):
        f = open(fileIn , 'rb')
        b = f.read()
        f.close()
        txt = bz2.decompress( b ).decode()
        elapsed = re.findall( '\d+' , txt )
        timeList = list( map( int , elapsed ) ) 
        # Split up the list


        print("processed")
        self.measurement = np.array( timeList )
        n_chars = MAX_CHAR - MIN_CHAR 
        self.measurement.shape = ( SECRET_LENGTH, n_chars ,N_TRIALS )
        
        
        print("ready to analyze??")
        
    def stats( self ):
        self.measurement[ self.measurement > BAD_MEASURMENT ] = np.mean( self.measurement )
        self.mean = np.mean( self.measurement , 2 )
        self.std  = np.std( self.measurement , 2 )
        self.median = np.median( self.measurement, 2 )
        self.sum = np.sum( self.measurement , 2 )
        self.min = np.min( self.measurement , 2 )
        

        self.best_sum = np.argmin( self.sum , axis=1 )
        self.best_min = np.argmin( self.min , axis=1 )
        self.best_median = np.argmin( self.median ,axis=1)
        self.bytes_min = self.best_min + MIN_CHAR
        self.bytes_sum = self.best_sum + MIN_CHAR
        self.ascii_min = struct.pack( "b"*len(self.bytes_min), *self.bytes_min)
        self.ascii_sum = struct.pack( "b"*len(self.bytes_sum), *self.bytes_sum)
        min_ints = np.array( [ int(x) for x in self.ascii_min] ) 
        sum_ints = np.array( [ int(x) for x in self.ascii_sum] )
        uncertain_bytes = np.abs( min_ints - sum_ints )
        print("I am the spectre ghost")
        print("Flag solved by best MINIMUM")
        print(f"{self.ascii_min}")
        print("Flag solved by best SUM")
        print(f"{self.ascii_sum}")
        print("Byte difference between the two methods ")
        print(uncertain_bytes )
        print("DONE")
        self.spectre_plot( 1 , self.min , "MIN")
        self.spectre_plot( 2 , self.sum , "SUM")
        plt.show()
    def spectre_plot( self , fignum , data , title):
        fig = plt.figure(fignum)
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8]) # main axes
        colors = [ (1,0,0) , ( 0 , 0 ,1 )] # R --> B
        c = ax.pcolor( data.transpose() ) #, vmin=7000, vmax=7001)
        ax.set_xlabel("flag byte")
        ax.set_ylabel(f"ASCII Character")

        ticks = range( 0 , MAX_CHAR-MIN_CHAR ,2 )
        labels = [ chr(x+MIN_CHAR) for x in ticks ]
        ax.set_yticks(ticks)
        ax.set_yticklabels(labels) 
        ax.set_title("Time Measured - " + title)
        fig.colorbar(c)

        
if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--file" , required=True)
    args = a.parse_args()
    a = StatAnalyzer(args.file)
    #a = StatAnalyzer("exespace/out.bz2")
    a.stats( )