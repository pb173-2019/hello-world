project(server)

add_executable(${PROJECT_NAME} main.cpp config.h database.h file_database.h file_database.cpp)
target_link_libraries(${PROJECT_NAME}
  mbedcrypto shared
)
