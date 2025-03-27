cmake_minimum_required(VERSION 3.14)
project(latency_solution CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(USE_LIGHTPCAPNG "Use LightPcapNg library instead of custom implementation" OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -fsanitize=address")

# LightPcapNg as a static dependency
if(USE_LIGHTPCAPNG)
    # Set paths for the static library
    set(LIGHTPCAPNG_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/lightpcapng")

    # Add LightPcapNg as a subdirectory to build it
    if(EXISTS "${LIGHTPCAPNG_SRC_DIR}/CMakeLists.txt")
        # Set option for static library build
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build LightPcapNg as static library" FORCE)

        # Configure LightPcapNg options
        set(LIGHT_USE_ZSTD OFF CACHE BOOL "Compile LightPcapNg without ZSTD support" FORCE)
        set(LIGHT_USE_ZLIB OFF CACHE BOOL "Compile LightPcapNg without ZLIB support" FORCE)
        set(BUILD_TESTING OFF CACHE BOOL "Don't build LightPcapNg tests" FORCE)

        # Build LightPcapNg
        add_subdirectory(${LIGHTPCAPNG_SRC_DIR} ${CMAKE_CURRENT_BINARY_DIR}/lightpcapng)

        # Define preprocessor macro to use LightPcapNg
        add_compile_definitions(USE_LIGHTPCAPNG)
    else()
        message(FATAL_ERROR "LightPcapNg source directory not found at ${LIGHTPCAPNG_SRC_DIR}. Please ensure the LightPcapNg library is in the lib/lightpcapng directory.")
    endif()
endif()

# Main executable
add_executable(solution
    src/main.cpp
    src/pcap_reader.cpp
    src/shared_queue.cpp
    src/protocol_parser.cpp
    src/orderbook.cpp
)

# PCAP dumper tool for debugging
add_executable(pcap_dumper
    src/pcap_dumper.cpp
    src/pcap_reader.cpp
    src/protocol_parser.cpp
)

target_include_directories(solution PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(pcap_dumper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Link necessary libraries
target_link_libraries(solution PRIVATE pthread)
target_link_libraries(pcap_dumper PRIVATE pthread)

if(USE_LIGHTPCAPNG)
    # Include LightPcapNg headers
    target_include_directories(solution PRIVATE ${LIGHTPCAPNG_SRC_DIR}/include)
    target_include_directories(pcap_dumper PRIVATE ${LIGHTPCAPNG_SRC_DIR}/include)

    # Link with LightPcapNg
    target_link_libraries(solution PRIVATE light_pcapng)
    target_link_libraries(pcap_dumper PRIVATE light_pcapng)
endif()

# Install rules
install(TARGETS solution DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS pcap_dumper DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})