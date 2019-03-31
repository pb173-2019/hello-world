project(includes)

include_directories(./)
include_directories(mbedtls/include)
include_directories(sqlite3)
include_directories(ed25519)


if (WIN64 OR WIN32 OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
    link_directories()
endif()

add_subdirectory(mbedtls)
add_subdirectory(sqlite3)


file(GLOB ed25519_src "ed25519/*.c" "ed25519/*.h")
add_library(ed25519 ${ed25519_src})
set_target_properties(ed25519 PROPERTIES LINKER_LANGUAGE C)