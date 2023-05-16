# Loads a flag and cleans up
import os
from sys import stderr

class Challenge:
    DEFAULT_FLAG = "FLAG_NOT_SET_SEE_ADMIN"

    def __init__( self ):
        self.loadFlag()
        self.loadPorts()
    def loadFlag( self ):
        self.flag = os.getenv( "FLAG" , Challenge.DEFAULT_FLAG)
        os.environ["FLAG"] =  "flag{This is not the flag}"

        if self.flag == Challenge.DEFAULT_FLAG:
            print("FLAG env is NOT set.", file=stderr)
    def loadPorts( self ):
        self.serviceHost = os.getenv( "SERVICE_HOST")
        self.servicePort = os.getenv( "SERVICE_PORT")

    def __repr__(self):
        return self.flag

    def getFlag(self):
        return self.flag
    def getPort( self ):
        if self.servicePort == None:
            print("Error -- port not set -- see admin", flush=True)
            raise ValueError
        return self.servicePort
    def getHost( self ):
        if self.serviceHost == None:
            print("Error -- host not set -- see admin", flush=True)
            raise ValueError
        return self.serviceHost
    @staticmethod
    def submit_ticket(r, ticket=""):
        ticket = ticket if ticket else os.getenv("TICKET", ticket)

        if ticket:
            r.recvuntil("Ticket please:")
            r.sendline(ticket.encode())
            print("Sent ticket")

def test():
    f = Challenge()
    assert(str(f) == Challenge.DEFAULT_FLAG)

    os.environ["FLAG"] =  "test_flag"
    f = Challenge()
    assert(str(f) == "test_flag")


if __name__ == "__main__":
    test()