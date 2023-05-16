#pragma once

#include <vector>
#include "LinkedList.hpp"
#include "PosFilter.hpp"

class User
{
    public:
        User();
        ~User();

        void menu();
        void loadPositions();
        void loadAccels();
        bool processChoice( int choice );

        void addMeasurement();
        void removeMeasurement();
        void printMeasurment(size_t idx , const PositionMeasurement &m );
        void listMeasurement();
        void run();

    protected:
        PositionUpdate update;
        LinkedList< PositionMeasurement > measurements;
        std::vector<AccelerationMeasurement> accels;
};

double us_to_sec( uint64_t us );
