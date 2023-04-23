cmake_minimum_required(VERSION 3.16.1)
project(OS_ex2)

set(CMAKE_CXX_STANDARD 11)

add_executable(OS_ex2 ex_2_tests_updated/tests/test5_no_out.cpp resources ex_2_tests_updated/uthreads.h ex_2_tests_updated/uthreads.cpp ex_2_tests_updated/output_files)
