
cmake_minimum_required(VERSION 3.15.0 )

project( ImagerScheduler )
# Create a list of cpp files that is a little easier to manage
set( sources 
    main.cpp
    scheduler.cpp
    scheduler.hpp
    globals.hpp
     )
add_executable( ImagerScheduler ${sources} )
target_link_libraries( ImagerScheduler PUBLIC m c)
target_compile_options( ImagerScheduler PUBLIC -std=c++17 -fPIC -O0)
