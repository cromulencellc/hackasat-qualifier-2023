import numpy as np
from scipy.spatial.transform import Rotation as R


class ValidationError( Exception ):
    pass

def MrpToQuaternion( mrp ):
    rodrigues = np.array( mrp )
 
    r = R.from_mrp( mrp )
    q_list = r.as_quat()
    # rectify the quaternion if the scalar field is negative
    if( q_list[3] < 0.0 ):
        q_list[3] = -q_list[3]
        q_list[0] = -q_list[0]
        q_list[1] = -q_list[1]
        q_list[2] = -q_list[2]
    # np quaternion is initialized differently than sci-py
    return q_list

def quatToDcm( Q ):
    rot = R.from_quat( Q )
    DCM_B2I = rot.as_matrix()
    DCM_I2B = np.transpose( DCM_B2I ) 
    return DCM_I2B

def quatToMrp( Q ):
    tol = 1.0e-6
    q4 = Q[3]
    if( (q4 <= 1-tol) and (q4 >= -1+tol)):
        # We are within range of a valid acos
        axis = np.array(  [Q[0], Q[1], Q[2]] ) 
        axis = axis / np.linalg.norm( axis )
        ang  = 2* np.arccos( Q[3])
        rodrigues = axis * np.tan(ang/4)
    elif( ( q4 < 1+tol) and ( q4 > 1-tol ) ):
        # Its numerically 1 - no rotation
        rodrigues = [0 , 0 , 0 ] 
        pass
    elif( (q4 > -(1+tol)) and ( q4 < -(1-tol)) ):
        # Its numerically -1 ----> 360 degrees No rotation
        rodrigues = [0 , 0 , 0 ] 
        pass
    else:
        print("Uhoh!")
        raise ValidationErr

    return rodrigues
def axisToQuat( bodyAxis , axisEci ):
    u = bodyAxis / np.linalg.norm( bodyAxis )
    v = axisEci / np.linalg.norm( axisEci )

    d = np.dot( u , v )
    q = np.array( [0.0,0.0,0.0,0.0])
    tolerance = 0.001
    # If u and v are equal or opposite then we cant use cross product to determine axis
    is1 = np.isclose( d , 1 , atol=tolerance)
    isM1 = np.isclose( d , -1 , atol=tolerance)
    if( is1 or isM1 ):
        rotAxis = np.argmin( bodyAxis )
        axis = [0,0,0]
        axis[rotAxis] = 1
        q[0:3] = axis
        q[3] = 1 + np.dot( u,v )
        pass
    else:
        q[0:3] = np.cross( u,v)
        q[3] = 1 + np.dot(u,v)

    
    q = q / np.linalg.norm( q )
    return q
def angleDifference( axis1Body ,axis2Eci , quat ):
    a1B = axis1Body / np.linalg.norm( axis1Body)
    a2E = axis2Eci / np.linalg.norm( axis2Eci )
    a1B.shape = (3,1)
    a2E.shape = (3,1)
    # Calculate quaternion as DCM
    rot_I2B = R.from_quat( quat )
    D_B2I = rot_I2B.as_matrix() #??
    #D_B2I = np.transpose( D_I2B )

    a1E = np.matmul(D_B2I , a1B )
    
    dot = np.dot( a1E.flatten() , a2E.flatten() )
    # Check out of bounds
    tol = 1.0e-6
    if(  dot > (1+ tol) or ( dot < (-1-tol)) ):
        raise ValidationError
    
    # Were good so we can use clippy
    dot = np.clip( dot ,-1.0, 1.0 )
    angle = np.arccos( dot )
    return angle