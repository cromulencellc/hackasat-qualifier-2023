#include "PosFilter.hpp"

PositionUpdate::PositionUpdate()
{
    posVariance = new PositionMeasurementVariance();
    C = Eigen::Matrix<double, 3,6>::Zero();
    C.block<3,3>( 0 ,0  ) = Eigen::Matrix3d::Identity();
}
PositionUpdate::~PositionUpdate()
{
    delete posVariance;
}

Eigen::Matrix<double,3,6> PositionUpdate::getC()
{
    return C;
}

void PositionUpdate::setVariance( double xx, double yy, double zz , double xy, double xz,  double yz )
{
    posVariance->varXX = xx;
    posVariance->varYY = yy;
    posVariance->varZZ = zz;
    posVariance->varXY = xy;
    posVariance->varXZ = xz;
    posVariance->varYZ = yz;
}
Eigen::Matrix<double,3,3> PositionUpdate::getR()
{
    Eigen::Matrix3d R;
    R << posVariance->varXX , posVariance->varXY , posVariance->varXZ,
         posVariance->varXY , posVariance->varYY , posVariance->varYZ,
         posVariance->varXZ , posVariance->varYZ , posVariance->varZZ;
    return R;
}
Eigen::Vector<double,3> PositionUpdate::getDy(const  Eigen::Vector<double,6> &state )
{
    
    Eigen::Vector3d dy;
    Eigen::Vector3d yExpected;
    Eigen::Vector3d yMeasure;

    yExpected << state[0],state[1],state[2];
    yMeasure << fixed_to_double<10>(measurement.x),fixed_to_double<10>(measurement.y),fixed_to_double<10>(measurement.z);
    //std::cout<<"Y: "<< yMeasure << std::endl;
    dy = yMeasure - yExpected;

    return dy;
}