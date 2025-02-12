#!/bin/bash

cmake -S . -B ./build &&
cmake --build ./build &&
sudo ./build/sniffer -o ./test.pcap -c 100;
