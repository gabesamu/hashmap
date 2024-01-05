cmake_minimum_required(VERSION 3.10)
project(hashmap)

set(SOURCES src/hashmap.c)

option(BUILD_SHARED_LIBS "Build as shared library" OFF)
if(BUILD_SHARED_LIBS)
    add_library(hashmap SHARED ${SOURCES})
else()
    add_library(hashmap STATIC ${SOURCES})
endif()

target_compile_features(hashmap PUBLIC c_std_99)
target_include_directories(hashmap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)


# Tests
option(BUILD_TESTS "Build tests" ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

if(BUILD_TESTS)
    add_executable(hashmap_tests tests/hashmap_tests.c)
    target_link_libraries(hashmap_tests PRIVATE hashmap)
endif()
