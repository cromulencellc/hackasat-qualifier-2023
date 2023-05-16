The mass distribution in a rigid body, such as a satellite, is described by a 3x3 symmetric matrix, known as the inertia matrix. The diagonals of this matrix are known as the moments of inertia, and they describe the inertia, or resistance to rotation, about each axis. The off-diagonal elements of this matrix are known as products of inertia, and they describe the cross-coupling between rotations in the different coordinate axes. In the general case, there is exactly one set of axes for which the products of inertia are zero; these
are known as the principal axes. Torque-free rotation is only stable about the major and minor principal axes (i.e., the principal axes corresponding to the smallest and largest principal moments of inertia). The principal inertias and axes can be found by computing the eigenvalues and eigenvectors of a non-principal inertia matrix.

Each satellite in this problem had a principal inertia matrix with only two distinct moments of inertia; the smaller principal inertia was unique, while the larger principal inertia was repeated. When a principal inertia matrix has repeated values, the principal axis is only distinct for the non-repeated inertia. This defines the plane in which the other two principal axes must lie, but the orientation of those axes within that plane is undefined. Any axis in that plane is thus a principal axis. We are told that the launch vehicle will deploy the satellite in geostationary orbit with the antenna facing nadir and the angular velocity matching the Earth’s rotation. Since a geostationary orbit is equatorial, the Earth angular velocity vector is perpendicular to the nadir vector. Therefore, if we place the antenna along the satellite’s minor (and unique) principal axis, the angular velocity vector will thus be along a major principal axis, so the rotation will be stable, and the antenna will remain pointed at nadir.

We computed the eigenvalues and eigenvectors of the inertia matrix in Python to identify the principal moments of inertia and corresponding principal axes. We then submitted the principal axis corresponding to the minimum principal moment of inertia.
```python
import numpy as np
I = np.array([[100., 0., 0.], [0., 500., 0.], [0., 0., 500.]]) # Enter values as appropriate for each satellite
w, v = np.linalg.eig(I)
min_axis_index = np.argmin(w)
min_axis = v[:, min_axis_index]
print(min_axis)
```