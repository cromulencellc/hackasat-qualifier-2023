#include "user.hpp"

#include <iostream>
#include <string>
double us_to_sec( uint64_t us )
{
    double secs(0.0);
    secs += static_cast< double >( us/1000000 ); // whole second part
    secs += static_cast< double >( (us%1000000) ) / 1.0e6 ; // partial seconds 
    return secs;
}

User::User()
{
    loadAccels();
    loadPositions();
    // NOTE: Makes no sense but puts it on the heap where we want it
    update.setVariance( 100.0 , 100.0 , 100.0 , 10.0 , 10.0, 10.0 );
}

User::~User()
{

}


void User::menu( )
{
    std::cout<<"1: Add measurement"<<std::endl;
    std::cout<<"2: Remove first measurement"<<std::endl;
    std::cout<<"3: Remove last measurement"<<std::endl;
    std::cout<<"4: List measurements"<<std::endl;
    std::cout<<"5: Run simulation"<<std::endl;
    std::cout<<"Choice>"<<std::endl;;
}
void User::loadAccels( )
{
    bool keepGoing(true);
    size_t sz;
    FILE *fp;
    fp = fopen("accels.bin","rb");

    while( true == keepGoing)    
    {
        AccelerationMeasurement accel;
        double data[3];
        uint64_t us;
        size_t read1,read2;
        read1 = fread(&us , sizeof(uint64_t), 1 , fp  );
        read2 = fread(data , sizeof(double), 3 , fp  );
        if( read1+read2 == 4 )
        {
            accel.x = data[0];
            accel.y =  data[1];
            accel.z =  data[2];
            accel.time_us =  us;
            accels.push_back( accel );
        }
        else
        {
            keepGoing = false;
        }
    }
    
}
void User::loadPositions( )
{
    bool keepGoing(true);
    size_t sz;
    FILE *fp;
    fp = fopen("positions.bin","rb");
    while( true == keepGoing)    
    {
        size_t read1,read2;
        PositionMeasurement newData;
        
        uint64_t data[3];
        uint64_t us;
        read1 = fread(&us , sizeof(uint64_t), 1 , fp  );
        read2 = fread(data , sizeof(uint64_t), 3 , fp  );
        if( (read1+read2) == 4 )
        {
            newData.x = data[0];
            newData.y =  data[1];
            newData.z =  data[2];
            newData.time_us = us;
            measurements.addBack( newData );
        }
        else
        {
            keepGoing = false;
        }
        
    }
    
}
bool User::processChoice( int choice )
{
    switch( choice )
    {
        case 1:
            addMeasurement();
            break;
        case 2:
            measurements.popFront();
            break;
        case 3:
            measurements.popBack();
            break;
        case 4: 
            listMeasurement( );
            break;
        case 5:
            run();
            break;
        default:
            menu();
            break;
    }
    return choice==5;
}

void User::run()
{
    size_t count;
    bool keep_going = true;
    PositionFilter filter;
    PositionMeasurement* nextMeasure = measurements.getFront();
    
    double tPos(0.0);
    std::cout<<"Running Kalman Filter"<<std::endl;
    std::cout<<"Position measurements have the following covariance matrix"<<std::endl;
    std::cout<< update.getR() << std::endl;

    double x = fixed_to_double<10>(nextMeasure->x);
    double y = fixed_to_double<10>(nextMeasure->y);
    double z = fixed_to_double<10>(nextMeasure->x);
    filter.init( x,y,z, 0,0,0 , 1000 ,1 );
    for(auto nextAccel : accels )
    {
        uint64_t nextAccelUs;
        
        nextAccelUs =  nextAccel.time_us ;
        double tAccel; 
        tAccel = us_to_sec( nextAccelUs );
        Eigen::Vector3d a;
        a << nextAccel.x , nextAccel.y, nextAccel.z ;
        filter.setAccel( a );
        
        if( nextMeasure->time_us < nextAccelUs )
        {
            // propegate to measure
            double tMeasure;
            tMeasure = us_to_sec( nextMeasure->time_us );
            filter.Propegate( tMeasure );
            // correct 
            update.measurement = *nextMeasure;
            filter.ApplyCorrection( &update );
            // propegate to end of accel

            filter.Propegate( tAccel ) ;
            // update to next measurement
            measurements.popFront(); // pop off the old one
            if( measurements.getFront() == nullptr ) 
            {
                update.measurement.time_us = 1000000000000;
            }
            else
            {
                nextMeasure = measurements.getFront(); // get the new one?
                
            }
            
        }   
        else
        {
            // propegate only
            filter.Propegate( tAccel );
        }
        filter.printState();
    }
    std::cout<<"Complete>"<<std::endl;

    filter.printPositionConfidence();
      
}


void User::addMeasurement( )
{   
    PositionMeasurement m;
    std::cout<<"Enter new measurement. X,Y,Z are uint64 fixed point numbers. Time is usec counts."<<std::endl;
    std::cout<<"Time (US)>"<<std::endl;
    std::cin >> m.time_us;
    std::cout<<"X>"<<std::endl;
    std::cin >> m.x;
    std::cout<<"Y>"<<std::endl;
    std::cin >> m.y;
    std::cout<<"Z>"<<std::endl;
    std::cin >> m.z;
    measurements.addBack( m );
    std::cout << std::endl;
}


void User::removeMeasurement( )
{
    int idx;
    std::cout<<"Which measurement number: "<<std::endl;
    std::cin >> idx;
    //out = measurements.getIndex( k );
}
void User::printMeasurment(size_t idx, const PositionMeasurement &m )
{
    double x,y,z;
    x = fixed_to_double<10>( m.x );
    y = fixed_to_double<10>( m.y );
    z = fixed_to_double<10>( m.z);
    printf( "Raw Measurement %zu: %llu %f %f %f\n", idx , m.time_us , x,y,z);
}

void User::listMeasurement()
{
    bool keep_going = true;
    size_t k = 0;
    PositionMeasurement* out;
    printf(" Time (us), X, Y, Z\n");
    while( keep_going )
    {
        out = measurements.getIndex( k );
        if( nullptr == out )
        {
            keep_going = false;
        }
        else
        {
            printMeasurment( k , *out );
        }
        k++;
        keep_going = ( out != nullptr );
    }
}