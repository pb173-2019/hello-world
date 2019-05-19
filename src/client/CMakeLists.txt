project(client)
configure_file(${CMAKE_SOURCE_DIR}/src/keys/server_pub.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

add_executable(${PROJECT_NAME} main.cpp
        transmission_net_client.h
        transmission_net_client.cpp
        config.h
        client_utils.h
        client.h
        client.cpp
        CMDapp.h
        CMDapp.cpp
        ChatWindow.h
        )

target_link_libraries(${PROJECT_NAME} mbedcrypto shared sqlite3 Qt5::Network Qt5::Core)
target_link_libraries(${PROJECT_NAME} ${CURSES_LIBRARIES})

