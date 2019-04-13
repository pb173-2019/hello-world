project(client)
configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

add_executable(${PROJECT_NAME} main.cpp
        transmission_net_client.h
        transmission_net_client.cpp
        config.h
        client.h
        client.cpp
        secure_channel.cpp
        secure_channel.h
        CMDapp.h
        CMDapp.cpp
        )
target_link_libraries(${PROJECT_NAME} mbedcrypto shared sqlite3 Qt5::Network Qt5::Core)

