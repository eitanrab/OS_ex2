#!/bin/bash 

g++ -std=c++11 uthreads.h uthreads.cpp tests/jona1.cpp -o tests/jona1
g++ -std=c++11 uthreads.h uthreads.cpp tests/jona2.cpp -o tests/jona2
g++ -std=c++11 uthreads.h uthreads.cpp tests/jona3.cpp -o tests/jona3
g++ -std=c++11 uthreads.h uthreads.cpp tests/jona4.cpp -o tests/jona4
g++ -std=c++11 uthreads.h uthreads.cpp tests/jona5.cpp -o tests/jona5
g++ -std=c++11 uthreads.h uthreads.cpp tests/jona6.cpp -o tests/jona6

g++ -std=c++11 uthreads.h uthreads.cpp tests/test1.in.cpp -o tests/drive1
g++ -std=c++11 uthreads.h uthreads.cpp tests/test2.in.cpp -o tests/drive2
g++ -std=c++11 uthreads.h uthreads.cpp tests/test3.in.cpp -o tests/drive3
g++ -std=c++11 uthreads.h uthreads.cpp tests/test4.in.cpp -o tests/drive4
g++ -std=c++11 uthreads.h uthreads.cpp tests/test5_no_out.cpp -o tests/drive5
g++ -std=c++11 uthreads.h uthreads.cpp tests/test6_no_out.cpp -o tests/drive6

chmod -R 700 .

cd tests
echo "Running jona1"
jona1
echo "Running jona2"
jona2
echo "Running jona3"
jona3
echo "Running jona4"
jona4
echo "Running jona5"
jona5
echo "Running jona6"
jona6
echo ""

echo "Running drive1"
drive1 &> ../output_files/drive1_res.out 
echo "Running drive2"
drive2 &> ../output_files/drive2_res.out
echo "Running drive3"
drive3 &> ../output_files/drive3_res.out
echo "Running drive4"
drive4 &> ../output_files/drive4_res.out
echo "drive test 1,2,3,4 outputs are in outputfiles directory compare them yourself"
echo ""

echo "Running drive5"
drive5
echo "Running drive6"
drive6

