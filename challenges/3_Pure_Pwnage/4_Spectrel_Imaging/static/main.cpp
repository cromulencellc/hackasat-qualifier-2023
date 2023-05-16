#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "globals.hpp"
#include "scheduler.hpp"
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include <utility>
#include <vector>
#include <iterator>


std::vector<size_t> read_vector()
{
    std::string line;
    std::getline( std::cin , line );
    if( std::cin.eof() )
    {
        std::exit(0);
    }
    if( line.size() > 512 )
    {
        throw std::exception();
    }
    std::vector<size_t> myVector;
    size_t i;
    std::istringstream os(line);
    while(os >> i)
    {
        myVector.push_back(i);
    }
    return myVector;
}
size_t read_int(  )
{
    std::string line;
    std::getline( std::cin , line );
    if( std::cin.eof() )
    {
        std::exit(0);
    }
    if( line.size() > 5 )
    {
        throw std::exception();
    }
    size_t out;
    std::istringstream os(line);
    os >> out;
    return out;
}
bool process_choice( Scheduler* s, uint8_t choice )
{
    std::string line;
    
    bool ok(true);
    size_t seq(0);
    size_t star(0);
    std::vector<size_t> multi;
    switch( choice )
    {

        case 0:
            s->ClearSequence();
            break;
        case 1:
            s->ExecuteSequence();
            ok = false;
            break;
        case 2:
            s->DisableTiming();
            break;
        case 3:
            s->EnableTiming();
            break;
        case 4:
            
            seq = read_int();
            s->ExecuteStarInSequence(seq);
            break;
        case 5:
            
            star = read_int();
            s->ExecuteStar( star );
            break;
        case 6:
            multi = read_vector( );
            if( multi.size() != 2 )
            {
                throw std::exception();
            }
                seq = multi[0];
                star = multi[1];
            s->ModifyToSequence( seq, star);
            break;
        case 7: 

            multi = read_vector(  );
            s->ExecuteStarInSequenceMulti( multi );
            break;

        default:
            ok = false;
            break;
    }
    return ok;
}



int main( void )
{
    bool keep_going(true);
    uint8_t choice;

    
    std::string line;
    Scheduler scheduler;
    scheduler.ClearSequence();

    scheduler.LoadStarTable();
    while (true == keep_going )
    {   
        int choice;
        choice = read_int();
        
        try
        {
            keep_going = process_choice(&scheduler ,choice ); 
        }
        catch(...)
        {
            // Dont do anything
        }
    }
    return 0;
}