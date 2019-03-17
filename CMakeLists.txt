cmake_minimum_required(VERSION 3.12)

project(helloworld)

#set (CMAKE_CXX_STANDARD 17) 17 cannot compile catch
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

SET(CMAKE_CXX_FLAGS -pthread)
SET(CMAKE_C_FLAGS -pthread)

# mbedtls settings
add_compile_definitions(MBEDTLS_CONFIG_FILE=<config.h>)
SET(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs.")
SET(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")

# system dependent functionality / using ELSE linux
if (${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN OR WIN32)
    add_compile_definitions(WINDOWS)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/mbedtls/include)
include_directories(${PROJECT_SOURCE_DIR}/include/sqlite3)

add_subdirectory(include/mbedtls)
add_subdirectory(include/sqlite3)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)
