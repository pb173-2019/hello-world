cmake_minimum_required(VERSION 3.12)

project(helloworld)

#set (CMAKE_CXX_STANDARD 17) 17 cannot compile catch
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

SET(CMAKE_CXX_FLAGS -pthread)
SET(CMAKE_C_FLAGS -pthread)

if (CMAKE_CXX_COMPILER_ID MATCHES Clang OR ${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
    set(CMAKE_CXX_FLAGS "-pedantic -Wall -Wextra -g -Og -Wold-style-cast")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    set(CMAKE_CXX_FLAGS "/permissive- /W4 /EHsc")
    add_definitions("-D_CRT_SECURE_NO_WARNINGS")
endif()

find_package(Qt5Network REQUIRED)
find_package(Qt5Core REQUIRED)

#set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
SET(CMAKE_AUTORCC ON)

# mbedtls settings
add_compile_definitions(MBEDTLS_CONFIG_FILE=<config.h>)
SET(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs.")
SET(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")

# system dependent functionality WINDOWS impementation ELSE assuming linux
if (WIN32 OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
    add_compile_definitions(WINDOWS)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/mbedtls/include)
include_directories(${PROJECT_SOURCE_DIR}/include/sqlite3)

add_subdirectory(include)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)
