from functools import wraps
import errno
import os
import signal

MINUTE = 60 # in seconds

class TimeoutError(Exception):
    pass

def timeout( seconds=None, error_message=os.strerror(errno.ETIME)):

    if None == seconds:
        try:
            secondsTimeout = int(os.getenv("TIMEOUT"))
        except:
            seconds = 90



    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator

