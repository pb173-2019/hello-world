cmake_minimum_required(VERSION 3.12)

project(helloworld)

#set (CMAKE_CXX_STANDARD 17) 17 cannot compile catch
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

SET(CMAKE_CXX_FLAGS -pthread)
SET(CMAKE_C_FLAGS -pthread)
# MSVC exceptions support
if (MSVC)
    SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /EHsc")
    SET (CMAKE_CPP_FLAGS "${CMAKE_CPP_FLAGS} /EHsc")
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
