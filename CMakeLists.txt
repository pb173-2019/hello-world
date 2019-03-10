cmake_minimum_required(VERSION 2.8.12)

enable_testing()

project(helloworld)

# mbedtls settings
add_compile_definitions(MBEDTLS_CONFIG_FILE=<config.h>)
SET(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs.")
SET(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/mbedtls/include)

add_subdirectory(include/mbedtls)
add_subdirectory(src/client)
add_subdirectory(src/server)
