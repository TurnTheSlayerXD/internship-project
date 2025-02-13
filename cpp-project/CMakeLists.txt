
cmake_minimum_required(VERSION 3.16)



set(CMAKE_CXX_STANDARD 20)

project(sniffer LANGUAGES CXX)


add_executable(sniffer src/main.cpp include/Record.h include/Sniffer.h include/SnifferParams.h src/Sniffer.cpp)


target_include_directories(sniffer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(sniffer PRIVATE ${CMAKE_SOURCE_DIR}/lib/pcap)
target_link_libraries(sniffer libpcap.a)

