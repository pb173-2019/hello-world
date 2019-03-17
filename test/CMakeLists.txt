
file(GLOB client_test_src "./client/*.h" "./client/*.cpp")
add_executable(client_test test_main.cpp ${client_test_src})
target_link_libraries(client_test shared)
add_test(client_test_execute client_test)

file(GLOB server_test_src "./server/*.h" "./server/*.cpp"
        ../src/server/config.h
        ../src/server/database.h
        ../src/server/file_database.cpp
        ../src/server/file_database.h
        ../src/server/server.cpp
        ../src/server/server.h
        )
add_executable(server_test test_main.cpp ${server_test_src})
target_link_libraries(server_test shared)
add_test(server_test_execute server_test)

file(GLOB shared_test_src "./shared/*.h" "./shared/*.cpp")
add_executable(shared_test test_main.cpp ${shared_test_src})

target_link_libraries(shared_test shared)
add_test(shared_test_execute shared_test)
