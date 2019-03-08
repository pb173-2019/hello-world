cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(wassup)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic")
# Configure compiler warnings
if (CMAKE_CXX_COMPILER_ID MATCHES Clang OR ${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
    # using regular Clang or AppleClang or GCC
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -Werror -pedantic") # -Wold-style-cast
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    # using Visual Studio C++
    set(CMAKE_CXX_FLAGS "/std:c++14 /permissive- /W4 /EHsc")
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
    set(MBED_TLS "-L${CMAKE_SOURCE_DIR}/libs/static/windows -lmbedtls -lmbedx509 -lmbedcrypto")# -mwindows
elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)
    set(MBED_TLS "-L${CMAKE_SOURCE_DIR}/libs/static/linux -lmbedtls -lmbedx509 -lmbedcrypto")
else()
    error("No support for your compiler. Use CLANG or CYGWIN")
endif()

enable_testing()

add_subdirectory(${CMAKE_SOURCE_DIR}/client)
add_subdirectory(${CMAKE_SOURCE_DIR}/server)




