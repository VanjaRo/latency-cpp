cmake_minimum_required(VERSION 3.14)
project(latency_solution CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(USE_LIGHTPCAPNG "Use LightPcapNg library instead of custom implementation" OFF)

# Log Level Option
set(LOG_LEVEL_OPTIONS NONE ERROR WARN INFO DEBUG TRACE)
set(CMAKE_LOG_LEVEL "INFO" CACHE STRING "Compile-time log level (NONE, ERROR, WARN, INFO, DEBUG, TRACE)")
set_property(CACHE CMAKE_LOG_LEVEL PROPERTY STRINGS ${LOG_LEVEL_OPTIONS})

# Validate the chosen level
if(NOT CMAKE_LOG_LEVEL IN_LIST LOG_LEVEL_OPTIONS)
    message(FATAL_ERROR "Invalid CMAKE_LOG_LEVEL specified: ${CMAKE_LOG_LEVEL}. Must be one of ${LOG_LEVEL_OPTIONS}")
endif()

# Map Log Level string to integer value for preprocessor
if(CMAKE_LOG_LEVEL STREQUAL "NONE")
    set(LOG_LEVEL_INT 0)
elseif(CMAKE_LOG_LEVEL STREQUAL "ERROR")
    set(LOG_LEVEL_INT 1)
elseif(CMAKE_LOG_LEVEL STREQUAL "WARN")
    set(LOG_LEVEL_INT 2)
elseif(CMAKE_LOG_LEVEL STREQUAL "INFO")
    set(LOG_LEVEL_INT 3)
elseif(CMAKE_LOG_LEVEL STREQUAL "DEBUG")
    set(LOG_LEVEL_INT 4)
elseif(CMAKE_LOG_LEVEL STREQUAL "TRACE")
    set(LOG_LEVEL_INT 5)
endif()

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Option to enable AddressSanitizer in Debug builds
option(ENABLE_ASAN "Enable AddressSanitizer for Debug builds" ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -fno-omit-frame-pointer")

# Set base debug flags
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

# Conditionally add ASan flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
endif()

# LightPcapNg as a static dependency
if(USE_LIGHTPCAPNG STREQUAL "ON")
    # Set paths for the static library
    set(LIGHTPCAPNG_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/LightPcapNg")

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
        add_compile_definitions(USE_LIGHTPCAPNG=1)
    else()
        message(FATAL_ERROR "LightPcapNg source directory not found at ${LIGHTPCAPNG_SRC_DIR}. Please ensure the LightPcapNg library is in the lib/LightPcapNg directory.")
    endif()
else()
    add_compile_definitions(USE_LIGHTPCAPNG=0)
endif()

# Main executable
add_executable(solution
    src/main.cpp
    src/shared_queue.cpp
    src/protocol_parser.cpp
    src/orderbook.cpp
    src/frame_processor.cpp
)

# Conditionally add pcap_reader.cpp only if USE_LIGHTPCAPNG is explicitly ON (equals "ON")
if(USE_LIGHTPCAPNG STREQUAL "ON")
    target_sources(solution PRIVATE src/pcap_reader.cpp)
endif()

# Add compile definition for log level to the main executable
target_compile_definitions(solution PRIVATE COMPILE_TIME_LOG_LEVEL=${LOG_LEVEL_INT})

# PCAP dumper tool for debugging - REMOVED
# add_executable(pcap_dumper
# src/pcap_dumper.cpp
# src/pcap_reader.cpp
# src/protocol_parser.cpp
# src/orderbook.cpp
# )

# Add compile definition for log level to the pcap_dumper tool as well - REMOVED
# target_compile_definitions(pcap_dumper PRIVATE COMPILE_TIME_LOG_LEVEL=${LOG_LEVEL_INT})
target_include_directories(solution PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# target_include_directories(pcap_dumper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src) # REMOVED

# Link necessary libraries
target_link_libraries(solution PRIVATE pthread)

# target_link_libraries(pcap_dumper PRIVATE pthread) # REMOVED
if(USE_LIGHTPCAPNG STREQUAL "ON")
    # Include LightPcapNg headers
    target_include_directories(solution PRIVATE ${LIGHTPCAPNG_SRC_DIR}/include)

    # target_include_directories(pcap_dumper PRIVATE ${LIGHTPCAPNG_SRC_DIR}/include) # REMOVED

    # Link with LightPcapNg
    target_link_libraries(solution PRIVATE light_pcapng)

    # target_link_libraries(pcap_dumper PRIVATE light_pcapng) # REMOVED
endif()

# Install rules
# Install binaries to a standard location within the build environment
install(TARGETS solution DESTINATION bin)

# install(TARGETS pcap_dumper DESTINATION bin) # REMOVED