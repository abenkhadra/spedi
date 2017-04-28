cmake_minimum_required(VERSION 3.2)
project(spedi CXX)

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  message(STATUS "Possible build types are Debug and Release.")
  set(CMAKE_BUILD_TYPE Debug)
else()
  message(STATUS "Current build type is ${CMAKE_BUILD_TYPE}")
endif()


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 ")

set(CMAKE_CXX_FLAGS_DEBUG "-ggdb3 -O0 -fno-inline -fno-omit-frame-pointer" CACHE STRING
    "Flags used by the C++ compiler for debug builds."
    FORCE)

set(CMAKE_CXX_FLAGS_RELEASE "-O3" CACHE STRING
    "Flags used by the C++ compiler for Release builds."
    FORCE)

set(CMAKE_VERBOSE_MAKEFILE OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(src)

if(CMAKE_PREFIX_PATH)
  include_directories(${CMAKE_PREFIX_PATH}/include)
endif()

add_subdirectory(src)

add_library(capstone STATIC IMPORTED)

find_library(capstone-path NAMES "libcapstone.a")
set_property(TARGET capstone PROPERTY IMPORTED_LOCATION ${capstone-path})

set(SOURCE_FILES main.cpp)

add_executable(spedi ${SOURCE_FILES})
add_dependencies(spedi elf++ dwarf++ disasm capstone)

target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libelf++.a)
target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libdwarf++.a)
target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libdisasm.a)
target_link_libraries(spedi capstone)
