#enable profiling: cmake -DPROFILER=TRUE
# clion: Settings -> Build -> Cmake -> Cmake options: add -DPROFILER=TRUE

if (PROFILER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")

    configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_priv.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
    configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

    add_executable(setup setup.cpp)
    target_link_libraries(setup mbedcrypto shared)

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

    add_executable(progiling_mock_files files.cpp ${sources_profiling})
    target_link_libraries(progiling_mock_files mbedcrypto shared sqlite3 Qt5::Core)

    add_executable(profiling_net net.cpp net.h ${sources_profiling}
            ../../src/server/net_utils.h
            ../../src/server/transmission_net_server.h
            ../../src/server/transmission_net_server.cpp
            ../../src/server/log_app.h
            ../../src/client/transmission_net_client.h
            ../../src/client/transmission_net_client.cpp
            )
    target_link_libraries(profiling_net mbedcrypto shared sqlite3 Qt5::Core Qt5::Network)
    set_property(SOURCE net.cpp PROPERTY SKIP_AUTOMOC ON)
endif()

