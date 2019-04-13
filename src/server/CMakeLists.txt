project(server)

add_executable(${PROJECT_NAME} main.cpp
        server.h
        server.cpp
        ../shared/requests.h
        database_server.h
        sqlite_database.h
        sqlite_database.cpp
        transmission_net_server.h
        )
target_link_libraries(${PROJECT_NAME}
  mbedcrypto shared sqlite3
)
