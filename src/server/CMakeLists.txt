project(server)

add_executable(${PROJECT_NAME} main.cpp
        server.h
        server.cpp
        requests.h
        database.h
        file_database.h
        file_database.cpp
        sqlite_database.h
        sqlite_database.cpp)
target_link_libraries(${PROJECT_NAME}
  mbedcrypto shared sqlite3
)
