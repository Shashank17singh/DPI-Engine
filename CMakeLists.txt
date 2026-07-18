cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 2.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

include_directories(${CMAKE_SOURCE_DIR}/include)

# Shared sources used by both executables
set(COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Simple, single-threaded version
add_executable(dpi_simple src/main_working.cpp ${COMMON_SOURCES})

# Multi-threaded, production version
add_executable(dpi_engine src/dpi_mt.cpp ${COMMON_SOURCES})
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)
