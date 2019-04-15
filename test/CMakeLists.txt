#copy keys from keys folder to bin test folder
configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_priv.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

file(GLOB client_test_src "./client/*.h" "./client/*.cpp"
        ../src/client/client.cpp
        ../src/client/transmission_net_client.h
        ../src/client/transmission_net_client.cpp

        ../src/server/database_server.h
        ../src/server/file_database.cpp
        ../src/server/file_database.h
        ../src/server/server.cpp
        ../src/server/server.h
        ../src/server/sqlite_database.cpp
        ../src/server/sqlite_database.h
        )
add_executable(client_test test_main.cpp ${client_test_src})
target_link_libraries(client_test shared sqlite3 Qt5::Network Qt5::Core)
add_test(client_test_execute client_test)

file(GLOB server_test_src "./server/*.h" "./server/*.cpp"
        ../src/server/transmission_net_server.h
        ../src/server/database_server.h
        ../src/server/file_database.cpp
        ../src/server/file_database.h
        ../src/server/server.cpp
        ../src/server/server.h
        ../src/server/sqlite_database.cpp
        ../src/server/sqlite_database.h
        )
add_executable(server_test test_main.cpp ${server_test_src} server/test_server_net.cpp server/test_server_net.h)
target_link_libraries(server_test shared sqlite3 Qt5::Network Qt5::Core)
add_test(server_test_execute server_test)

file(GLOB shared_test_src "./shared/*.h" "./shared/*.cpp")
add_executable(shared_test test_main.cpp ${shared_test_src})
target_link_libraries(shared_test shared eddsa)
add_test(shared_test_execute shared_test)
