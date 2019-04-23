#enable profiling: cmake -DPROFILER=TRUE
# clion: Settings -> Build -> Cmake -> Cmake options: add -DPROFILER=TRUE

if (PROFILER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")

    configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_priv.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
    configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

    file(GLOB sources_profiling
            ../../src/server/transmission_file_server.h
            ../../src/server/database_server.h
            ../../src/server/file_database.cpp
            ../../src/server/file_database.h
            ../../src/server/server.cpp
            ../../src/server/server.h
            ../../src/server/sqlite_database.cpp
            ../../src/server/sqlite_database.h
            ../../src/client/client.cpp
            ../../src/client/transmission_file_client.h
            )

    add_executable(profiling1 scenario1.cpp ${sources_profiling})
    target_link_libraries(profiling1 mbedcrypto shared sqlite3 Qt5::Core)

    add_executable(setup setup.cpp)
    target_link_libraries(setup mbedcrypto shared)
endif()

