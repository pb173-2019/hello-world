project(server)

add_executable(${PROJECT_NAME} main.cpp
        database.h
        file_database.h
        file_database.cpp
        file_tranmission_manager.h
        sqlite_database.h
        sqlite_database.cpp)
target_link_libraries(${PROJECT_NAME}
  mbedcrypto shared sqlite3
)
