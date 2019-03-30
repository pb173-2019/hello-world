project(includes)

include_directories(./)
include_directories(mbedtls/include)
include_directories(sqlite3)
include_directories(xeddsa)
include_directories(sodium)

if (WIN64)
  link_directories()
endif()

add_subdirectory(mbedtls)
add_subdirectory(sqlite3)

file(GLOB xeddsa_src xeddsa/*.c xeddsa/*.h)
list(REMOVE_ITEM xeddsa_src "xeddsa/tests.c")
add_library(xeddsa ${xeddsa_src})

