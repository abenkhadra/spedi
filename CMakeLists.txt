cmake_minimum_required(VERSION 3.2)
project(spedi)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14\
    -fno-omit-frame-pointer")
#    -fsanitize=address")
#    -fsanitize-blacklist=${CMAKE_SOURCE_DIR}/blacklist.txt")

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(src)

add_subdirectory(src)

add_library(capstone STATIC IMPORTED)
set_property(TARGET capstone PROPERTY IMPORTED_LOCATION /usr/lib/libcapstone.a)

set(SOURCE_FILES ${CMAKE_SOURCE_DIR}/src/util/cmdline.h main.cpp)

add_executable(spedi ${SOURCE_FILES} main.cpp)

add_dependencies(spedi elf++ dwarf++ disasm capstone)

target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libelf++.a)
target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libdwarf++.a)
target_link_libraries(spedi ${CMAKE_SOURCE_DIR}/lib/libdisasm.a)
target_link_libraries(spedi capstone)

