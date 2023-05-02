cmake_minimum_required(VERSION 3.16.1)
project(OS_ex2)

add_library(uthreads uthreads.h uthreads.cpp)

set_property(TARGET uthreads PROPERTY CXX_STANDARD 11)
target_compile_options(uthreads PUBLIC -Wall -Wextra)

add_subdirectory(tests_os_ex2-main)

add_executable(OS_ex2  ex_2_tests_updated/uthreads.h ex_2_tests_updated/uthreads.cpp ex_2_tests_updated/output_files)
