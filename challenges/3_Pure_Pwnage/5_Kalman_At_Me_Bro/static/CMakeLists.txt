cmake_minimum_required(VERSION 3.15.0 )
#set( CMAKE_TOOLCHAIN_FILE aarch64.cmake )
project( Kalman )


# Create a list of cpp files that is a little easier to manage
set( sources 
    main.cpp
    user.cpp
    PosFilter.cpp
     )

add_executable( Kalman ${sources} )

target_include_directories( Kalman PUBLIC /usr/include/eigen3 includes)
target_compile_definitions( Kalman PUBLIC EIGEN_NO_MALLOC ) 
target_link_libraries( Kalman PUBLIC m c)
target_compile_options( Kalman PUBLIC -std=c++11)

#set( PatchCmd "--set-interpreter ../../.glibc/glibc_2.31_no-tcache/ld-2.31.so --set-rpath ../../.glibc/glibc_2.31_no-tcache/ Kalman")
#add_custom_target( ALL
#    COMMAND
#)