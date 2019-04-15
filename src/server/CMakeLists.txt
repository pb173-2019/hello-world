project(server)

configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_priv.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

add_executable(${PROJECT_NAME} main.cpp
        server.h
        server.cpp
        ../shared/requests.h
        database_server.h
        sqlite_database.h
        sqlite_database.cpp
        transmission_net_server.h
        log_app.h)
target_link_libraries(${PROJECT_NAME} mbedcrypto shared sqlite3  Qt5::Network Qt5::Core)
