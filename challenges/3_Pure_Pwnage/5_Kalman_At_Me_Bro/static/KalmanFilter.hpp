#pragma once
#include <Eigen/Dense>

#include <iostream>
template< size_t N , size_t M> class KalmanUpdate
{
public:
    KalmanUpdate(){}
    ~KalmanUpdate(){}

    
    virtual Eigen::Matrix<double,M,N> getC() = 0;
    virtual Eigen::Matrix<double,M,M> getR() = 0;
    virtual Eigen::Vector<double,M> getDy(const  Eigen::Vector<double,N> &state ) = 0;

};

template<size_t N , size_t M > class ExtendedKalmanFilter
{

public:
    ExtendedKalmanFilter() : 
        currentTime_(0.0),
        lastTime_(0.0)
    {

    }
	~ExtendedKalmanFilter()
    {

    }

    void Propegate( double time )
    {
        currentTime_ = time;
        LinearizeEom( currentTime_, x_ );
        A_ = getA();
        Q_ = getQ();
        G_ = getG();
        TimeUpdate( currentTime_ );
        x_ = PropegateEom( currentTime_ , x_);
        lastTime_ = currentTime_;
    }
    virtual Eigen::Vector<double,N> PropegateEom( double time ,const Eigen::Vector<double,N> &state ) = 0;
    virtual void LinearizeEom( double time , const Eigen::Vector<double,N> &state) = 0;
    
    virtual Eigen::Matrix<double,N,N> getA(  ) =0;
    virtual Eigen::Matrix<double,N,M> getG(  ) =0;
    virtual Eigen::Matrix<double,M,M> getQ(  ) =0;

    

    void TimeUpdate( double currentTime )
    {
        double dt(0.0);
        dt = currentTime - lastTime_;
        Eigen::Matrix<double,N,N> STM;
        STM = Eigen::Matrix<double,N,N>::Identity() + A_*(dt);
        P_ = STM*P_*STM.transpose() + G_*(Q_*G_.transpose());
        lastTime_ = currentTime;
    }

    template< size_t MEAS_COUNT> void ApplyCorrection( KalmanUpdate<N,MEAS_COUNT> *update)
    {

        Eigen::Matrix<double, MEAS_COUNT, MEAS_COUNT> R;
        Eigen::Matrix<double, MEAS_COUNT,N> C;
        Eigen::Vector<double, MEAS_COUNT> dy;
        C = update->getC();
        R = update->getR();
        dy = update->getDy(x_);
        Eigen::Matrix<double ,MEAS_COUNT  ,MEAS_COUNT > S;
        Eigen::Matrix<double, N ,  MEAS_COUNT> K;
        Eigen::Vector<double, N >  dx;
        S = ( C * ( P_ * C.transpose() ) ) + R;
        K = P_ * (  C.transpose() *  S.inverse() );
        //std::cout<<"P: "<<P_<<std::endl;
        //std::cout<<"S: "<<S<<std::endl;

        P_ = P_ - K*C*P_;
        //std::cout<<"K: "<<K<<std::endl;
        dx  = K * dy;
        //std::cout<<"DX: "<<dx<<std::endl;
        x_ = x_ + dx;
    }
    void setP(const Eigen::Matrix<double,N,N> &Pin )
    {
        P_ = Pin;
    }
    void setState( const Eigen::Vector<double,N> &xIn )
    {
        x_ = xIn;
    }
protected:

    Eigen::Matrix<double,N,N> P_;
    Eigen::Vector<double,N> x_;
    Eigen::Matrix<double,N,M> G_;
    Eigen::Matrix<double,N,N> A_;
    Eigen::Matrix<double,M,M> Q_;
    double currentTime_;
    double lastTime_;
};

