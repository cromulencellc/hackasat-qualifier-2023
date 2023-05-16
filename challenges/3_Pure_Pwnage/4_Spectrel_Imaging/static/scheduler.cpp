#include "scheduler.hpp"
#include <x86intrin.h>
#include <vector>
#include <iostream>
#include "globals.hpp"
#include <string.h>
#include <fstream> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

Scheduler::Scheduler() : 
timingOn_(false),
start(0)
{
    MaxSequenceSize = SEQUENCE_SIZE;
    MaxStarNumber = N_STARS;
    std::string flag;
    std::ifstream f;
    f.open("flag.txt");
    std::getline( f , flag );
    f >> flag;
    strcpy( secret , flag.c_str() );
    memset( CommandSequence , 0 , SEQUENCE_SIZE );
    fd = open("/fpga/spectral",O_NONBLOCK );
}
Scheduler::~Scheduler()
{
    close( fd );
}   

void Scheduler::burn_count( size_t count )
{
    for(volatile size_t k=0; k < count; k ++ )
    {
        // just chillin'
    }
}

void Scheduler::start_timer()
{   
    unsigned int junk;
    if( true == timingOn_)
    {
        start = __rdtscp( &junk );
    }
}

void Scheduler::stop_timer()
{
    uint64_t stop;
    uint64_t elapsed;
    unsigned int junk;

    if( true == timingOn_ )
    {
        stop =  __rdtscp( &junk );
        elapsed = stop - start;
        std::cout<<"Elapsed: "<< elapsed << std::endl;
    }
}
void Scheduler::EnableTiming( )
{
    timingOn_ = true;
}
void Scheduler::DisableTiming( )
{
    timingOn_ = false;
}
void Scheduler::write_device( void *ptr , size_t bytes )
{
    write( fd , ptr , bytes );

}
void Scheduler::ExecuteStar( size_t star_number )
{   
    start_timer();
    char *out;
    if( star_number < N_STARS )
    {
        out = StarCatalog[star_number]  ;
        write_device( out  , strnlen(out ,COMMAND_SIZE));    }
    else
    {
        throw ScheduleError();
    }
    stop_timer();
}
void Scheduler::ExecuteStarInSequence( size_t sequence_id )
{
    // TODO PUT ME IN A REASONABLE SPOT
    _mm_clflush(&MaxSequenceSize);
    _mm_mfence();
    // "burn" a little to give the cache time to flush
    burn_count( 100 );
    //END TODO
    start_timer();
    if( sequence_id < MaxSequenceSize )
    {
        char* out;
        // CommandSequence[sequenceIdx] will be the flag if we access it out of bounds
        // the if statement checking agianst SEQUNCE_SIZE should protect us but we can force
        // the value into the L2 cache via speculative exe
        out = StarCatalog[ CommandSequence[sequence_id] ] ;        
        write_device( out  , strnlen(out ,COMMAND_SIZE));
    }
    else
    {
        throw ScheduleError();
    }
    stop_timer();
}
void Scheduler::ExecuteStarInSequenceMulti(const std::vector<size_t> &in)
{
    //for(size_t item : in ) // WONT TRAIN THE BRANCH PREDICTOR!?!?!
    for( size_t k = 0 ; k < in.size() ; k++)
    {
        // This function is already timed - dont add more timing 
        ExecuteStarInSequence( in[k] );
    }
}

void Scheduler::ExecuteSequence()
{
    start_timer();
    for( size_t k =0; k < MaxSequenceSize ; k++ )
    {
        ExecuteStarInSequence( k );
    }
    stop_timer();
}
void Scheduler::ModifyToSequence( size_t sequence_id  , size_t star_number )
{
    start_timer();
    if( sequence_id < MaxSequenceSize )
    {
        if( star_number < MaxStarNumber )
        {
            CommandSequence[ sequence_id ] = star_number;
        }
        else
        {
            throw ScheduleError();
        }
    }
    else
    {
        // do nothing
        throw ScheduleError();
    }
    stop_timer();
}
void Scheduler::ClearSequence( )
{

    start_timer();
    for( size_t k = 0 ; k < MaxSequenceSize ; k++ )
    {
        CommandSequence[ k ] = INVALID_SEQENCE; 
    }
    // evict the possible locations in StarCatalog out of the cache
    // send me before i train the branch prediction unit
    _mm_mfence();
    // 

    for (size_t i = 0; i < N_STARS; i++ )
    {
        for( size_t k=0; k < COMMAND_SIZE/8; k++ )
        {
            char* ptr =  &StarCatalog[ i ][k*8];
            _mm_clflush( ptr ); 
        }
        
    }

    _mm_clflush(&MaxSequenceSize);
    _mm_clflush(&MaxStarNumber);
    
    
    _mm_mfence();

    stop_timer();
}

void Scheduler::LoadStarTable( )
{
    std::string line;
    std::ifstream f( "stars.csv"); 
    std::cout<<"Loading star catalog"<<std::endl;
    // Clear out yo clunk
    memset( StarCatalog , 0 , COMMAND_SIZE*N_STARS);
    for( size_t k=0; k < N_STARS; k++  )
    {
        std::getline( f , line);
        strncpy( StarCatalog[k] , line.c_str(), COMMAND_SIZE);
    }
    std::cout<<"Loaded"<<std::endl;
}
