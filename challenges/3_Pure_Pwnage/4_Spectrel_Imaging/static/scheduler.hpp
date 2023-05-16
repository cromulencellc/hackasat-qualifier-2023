#pragma once 
#include <string>
#include <exception>
#include "globals.hpp"
#include <vector>
class ScheduleError : public std::exception
{
    char * what () {
        return "Schedule Error";
    }
};

class Scheduler
{
    public: 
        Scheduler();
        ~Scheduler();
        
        void LoadStarTable( );
        void EnableTiming( );
        void DisableTiming( );
        void ExecuteStar( size_t star_number );
        void ExecuteStarInSequence( size_t sequence_id );
        void ExecuteStarInSequenceMulti( const std::vector<size_t> &in);
        void ExecuteSequence();
        void ModifyToSequence( size_t sequence_id  , size_t star_number );
        void ClearSequence( );
        void ModifySequence( size_t sequence_id , size_t star_number );
        void burn_count( size_t counts  );

    protected:
        void start_timer( );
        void stop_timer( );

        void write_device( void *ptr , size_t bytes );
        int fd;
        uint64_t start;
        bool timingOn_;
        uint16_t MaxSequenceSize;
        uint16_t MaxStarNumber;
        char StarCatalog[N_STARS][COMMAND_SIZE]; //StarID 102, q0 ,q1,q2,q3, LY
        uint8_t CommandSequence[SEQUENCE_SIZE];
        char secret[256]; 

        //
        
};