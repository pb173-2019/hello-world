project(client)

add_executable(${PROJECT_NAME} main.cpp
        client.h
        client.cpp
        connection.h
        connection.cpp
        secure_channel.cpp
        secure_channel.h
        transmission_file_client.h
        )
target_link_libraries(${PROJECT_NAME} mbedcrypto shared sqlite3)

