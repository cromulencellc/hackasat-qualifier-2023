#include <iostream>
#include "PosFilter.hpp"
#include "user.hpp"



int main(void)
{
    bool exit = false;
    User user;
    while( false == exit )
    {
        int choice;
        user.menu();
        std::cin >> choice;
        if( std::cin.fail() )
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            continue;
        }

        exit = user.processChoice( choice );
        
    }

    std::cout<<"Filter Exit"<<std::endl;
    return 0;
}

