cmake_minimum_required(VERSION 3.10)
project(disable_ipv6)

set(CMAKE_C_STANDARD 11)

option(VERBOSE "Verbose prints to stderr" OFF)

add_library(disable_ipv6 SHARED disable_ipv6.c)
target_link_libraries(disable_ipv6 PRIVATE dl)

if (VERBOSE)
    target_compile_definitions(disable_ipv6 PRIVATE VERBOSE)
endif (VERBOSE)
