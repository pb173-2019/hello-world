project(client)

add_executable(${PROJECT_NAME} main.cpp
        transmission_net_client.h
        transmission_net_client.cpp
        config.h
        client.h
        client.cpp
        secure_channel.cpp
        secure_channel.h
        CMDapp.h
        )
target_link_libraries(${PROJECT_NAME} mbedcrypto shared sqlite3 Qt5::Network Qt5::Core)

