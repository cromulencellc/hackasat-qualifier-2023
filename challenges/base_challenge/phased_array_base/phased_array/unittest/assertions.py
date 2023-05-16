import numpy as np


def ASSERT_NEAR( a , b , text ,tolerance=1e-6):
    diff = np.abs( a - b )

    assert diff < tolerance, f"Near assertion: {text}"
