#pragma once
#include "KalmanFilter.hpp"

#include <iostream>

struct PositionMeasurement
{
    uint64_t time_us;
    uint64_t x;
    uint64_t y;
    uint64_t z;
};

struct PositionMeasurementVariance
{
    double varXX;
    double varYY;
    double varZZ;
    double varXY;
    double varXZ;
    double varYZ;
};

template< size_t FRACTION_BITS> double fixed_to_double( const int64_t &in)
{
    constexpr int64_t scalar = ( 2 << (FRACTION_BITS-1) );
    double f;
    f = static_cast<double>( in ) / static_cast<double>( scalar ) ;
    return f;
}

class PositionUpdate : public KalmanUpdate<6,3>
{
    public:
        PositionMeasurement measurement;

        PositionUpdate();
        ~PositionUpdate();
        virtual Eigen::Matrix<double, 3,6> getC();
        virtual Eigen::Matrix<double,3,3> getR();
        virtual Eigen::Vector<double,3> getDy(const  Eigen::Vector<double,6> &state );
        void setVariance(double xx, double yy, double zz , double xy, double xz,  double yz  );
    protected:
        Eigen::Matrix<double,3,6> C;
        PositionMeasurementVariance *posVariance; 
};

struct AccelerationMeasurement
{
    double x;
    double y;
    double z;
    uint64_t time_us;
};



class PositionFilter : public ExtendedKalmanFilter<6,3>
{

    
public:
    PositionFilter() : accelVariancePerStep( 0.01 )
    {

    }
    ~PositionFilter(){}
    void printState( )
    {
        printf("Estimated %f: %f,%f,%f\n", lastTime_ , lastPos_[0], lastPos_[1], lastPos_[2] ) ;
    }
    void printPositionConfidence()
    {
        std::cout<<"Position Covariance"<<std::endl<< P_.block<3,3>(0,0) << std::endl;
    }
    void init( double x, double y, double z, double vx , double vy, double vz , double Px, double Pv )
    {

        Eigen::Vector<double,6> initState;
        Eigen::Matrix<double,6,6> initP;
        initState << x,y,z,vx,vy,vz;
        initP = Eigen::Matrix<double,6,6>::Zero();
        initP.block<3,3>(0,0) = Eigen::Matrix3d::Identity()*Px;
        initP.block<3,3>(3,3) = Eigen::Matrix3d::Identity()*Pv;
        setState( initState );
        setP( initP );
    }
    virtual Eigen::Vector<double,6> PropegateEom(double time, const Eigen::Vector<double,6> &state)
    {
        Eigen::Vector3d velocity;
        Eigen::Vector3d position;

        position << state[0], state[1], state[2];
        velocity << state[3], state[4], state[5];
        double dt;
        
        dt = time - lastTime_;
        
        position = position + ( velocity * dt ) + ( 0.5 * accel_ * dt * dt );
        velocity = velocity + ( accel_    * dt );
        lastTime_ = time;
        Eigen::Vector<double,6> out;
        out = Eigen::Vector<double,6>::Zero();
        out(0) = position(0);
        out(1) = position(1);
        out(2) = position(2);
        out(3) = velocity(0);
        out(4) = velocity(1);
        out(5) = velocity(2);
        lastPos_  = position;
        return out;
    }

    virtual void LinearizeEom(double time, const Eigen::Vector<double,6> &state )
    {

        A = Eigen::Matrix<double,6,6>::Zero();
        G = Eigen::Matrix<double,6,3>::Zero();
        Q = Eigen::Matrix3d::Identity() * accelVariancePerStep;
        A.block<3,3>(0,3) = Eigen::Matrix<double,3,3>::Identity();
        G.block<3,3>(3,0) = Eigen::Matrix<double,3,3>::Identity();

        //std::cout<<"A: "<<A<<std::endl;
        //std::cout<<"G: "<<G<<std::endl;
    }

    void setAccel( Eigen::Vector3d a )
    {
        accel_ = a;
    }
    virtual Eigen::Matrix<double,6,6> getA(  )
    {
        return A;
    }
    virtual Eigen::Matrix<double,6,3> getG(  )
    {
        return G;
    }
    virtual Eigen::Matrix<double,3,3> getQ(  )
    {
        return Q;
    }

protected:
    Eigen::Vector3d lastPos_;
    double accelVariancePerStep;
    Eigen::Vector3d accel_;
    double lastTime_;
    Eigen::Matrix<double,6,6> A;
    Eigen::Matrix<double,6,3> G;
    Eigen::Matrix<double,3,3> Q;
};