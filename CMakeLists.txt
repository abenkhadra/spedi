cmake_minimum_required(VERSION 3.2)
project(elfparse)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fno-omit-frame-pointer")

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(modules)

add_subdirectory(modules)

add_library(capstone STATIC IMPORTED)

set(SOURCE_FILES ${CMAKE_SOURCE_DIR}/modules/util/cmdline.h main.cpp)

add_executable(dithumb ${SOURCE_FILES} main.cpp)

add_dependencies(dithumb elf++ dwarf++ disasm capstone)

target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libelf++.a)
target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libdwarf++.a)
target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libdisasm.a)
target_link_libraries(dithumb /usr/lib/libcapstone.a)

