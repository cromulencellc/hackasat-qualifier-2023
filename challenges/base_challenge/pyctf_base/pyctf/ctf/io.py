import sys 
import numbers
import numpy as np
import binascii

class IoError( Exception):
    pass
# Print a string
def outputStr( msg ):
    print( msg , flush=True)
# Print a hexlified string
def outputHex( msg : bytes ) -> bytes:
    output = b""

    try:
        output = binascii.hexlify(msg)
    except binascii.Error as e:
        raise IoError
    except Exception as e:
        raise IoError

    return output
# Load a number with decimal points
def input_number( msg ):
    strInput = input(msg)
    try: 
        floatInput = float( strInput )
        if not isInstance( floatInput,  numbers.Number ):
            print("Input is not a number", flush=True)
            raise IoError
        if not np.isfinite( floatInput ):
            print("Number is not finite", flush=True)
            raise IoError
    except:
        raise IoError        
    return floatInput 
def input_number_array( msg , nItems):
    strInput = input( msg + " " )
    try: 
        listified = strInput.split(",")
        numberArray = np.array( listified ).astype( float )
        N = len(numberArray)
        if N != nItems :
            print(f"You entered an array with {N} items, expected {nItems} items", flush=True )
            raise IoError
        for item in numberArray:
            if not np.isfinite( item ):
                print(f"Array item {item} is not finite.")
                raise IoError
    except:
        print("Expected format of array input is 'X1,X2,X3,....,XN'", flush=True)
        raise IoError
    return numberArray
def input_int_array( msg , nItems):
    strInput = input( msg + " " )
    try: 
        listified = strInput.split(",")
        numberArray = np.array( listified ).astype( int )
        isInt = np.issubdtype( numberArray.dtype, int )
        N = len(numberArray)
        if N != nItems :
            print(f"You entered an array with {N} items, expected {nItems} items", flush=True )
            raise IoError
        if False == isInt:
            print(f"Array should only contain integers.")
            raise IoError
    except:
        print("Expected format of array is comma seperated integers for example: '1,2,3,....,N'", flush=True)
        raise IoError
    return numberArray
def input_hex( msg, min_len_bytes=-1, max_len_bytes=-1):
    strInput = input( msg + " " )

    output = b""

    if min_len_bytes > max_len_bytes:
        raise IoError("Impossible min and max parameters")

    try:
        output = binascii.unhexlify(strInput)

        if min_len_bytes >= 0 and len(output) < min_len_bytes:
            print(f"You entered hex with size {len(output)}, expected size greater than {min_len_bytes} bytes", flush=True )
            raise IoError
        if max_len_bytes >= 0 and len(output) > max_len_bytes:
            print(f"You entered hex with size {len(output)}, expected size less than {max_len_bytes} bytes", flush=True )
            raise IoError

    except binascii.Error as e:
        print(f"Got badly formatted hex: {e.args[0]}", flush=True)
        raise IoError
    except Exception as e:
        print("Got badly formatted hex. Expected input as hexlified string. Example: 'deadbeef'", flush=True)
        raise IoError
    return output
def input_int( msg ):
    strInput = input(msg)
    try: 
        intInput = int( strInput )
    except:
        print("Input is not an integer", flush=True)
        raise IoError
    return intInput
def input_str( msg ):
    strInput = input( msg )
    return strInput

def test():
    try:
        outputHex("this should fail")
    except IoError as e:
        print("Passed")
    
    outputHex(b"This should pass")


    input_hex("Input: ", 1, 2)
    input_hex("Input: ", 1, 1)
    input_hex("Input: ", 1, 1)


if __name__ == "__main__":
    test()
