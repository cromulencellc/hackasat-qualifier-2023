import web
import ctf.challenge as CHAL
import ctf.io as IO
import ctf.timeout as TO
import multiprocessing
import values
@TO.timeout( 120 )
def challenge():
    c = CHAL.Challenge()
    webProc = multiprocessing.Process( target=web.run_web , daemon=True)
    webProc.start()

    IO.outputStr(f"Math problem available at http://{c.getHost()}:{c.getPort()}/math")
    answer = IO.input_int("What is the solution to the math problem? ")
    expected = values.a * values.b

    if( answer == expected ):
        print("Here is your flag")
        IO.outputStr( c.getFlag() )
    else:
        print("WRONG!")

if __name__ == "__main__":
    try: 
        challenge()
    except TimeoutError:
        print("Timeout....bye")
