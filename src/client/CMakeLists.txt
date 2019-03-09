
include_directories(${CMAKE_SOURCE_DIR}/libs/include)

include_directories(${CMAKE_SOURCE_DIR}/client/include)

set( SOURCE
        Client.h
        Connection.h
        SecureChannel.h
        )

add_executable(Client ${SOURCE})
#target_link_libraries(Client ${MBED_TLS})

add_executable(test_p1
        test/test-main.cpp
        test/test-impl.cpp
        ${SOURCE}
        )
#target_link_libraries(test_p1 ${MBED_TLS})

#testing files
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/long.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/out.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/no_permissions.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupted.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupt1.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupt2.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

add_test(test_p1_run test_p1)

