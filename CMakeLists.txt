cmake_minimum_required(VERSION 3.10)

# Project information
project(PcapParser
    VERSION 1.0.0
    DESCRIPTION "A C++ PCAP file parser with CSV output"
    LANGUAGES CXX
)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

# Create output directories
file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find PcapPlusPlus
find_package(PcapPlusPlus CONFIG REQUIRED)

# Source files
set(SOURCES
    main.cpp
    PcapParser.cpp
)

set(HEADERS
    PcapParser.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Link libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        PcapPlusPlus::Packet++
        PcapPlusPlus::Pcap++
        wpcap
        ws2_32
        iphlpapi
    )
elseif(APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        PcapPlusPlus::Packet++
        PcapPlusPlus::Pcap++
        pcap
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE
        PcapPlusPlus::Packet++
        PcapPlusPlus::Pcap++
        pcap
        pthread
    )
endif()

# Compiler flags
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Installation
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

# Print configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
