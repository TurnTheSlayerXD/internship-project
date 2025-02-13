#!/bin/bash

cmake -S . -B ./build &&
cmake --build ./build &&
sudo ./build/sniffer -o ./test.csv -c 10 -t 2 -i eth0
