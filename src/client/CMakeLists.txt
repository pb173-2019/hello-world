include_directories(${CMAKE_SOURCE_DIR}/libs/include)
set( SOURCE
        AES_CBC_PKCS7_SHA512.hpp
        AES_CBC_PKCS7_SHA512.cpp
        ApplicationHelp.hpp
        CommandLineArgument.hpp
        CipherWrapper.hpp
        SHAWrapper.hpp
        HexUtils.hpp
        Print.cpp
        Print.hpp )

add_executable(project1 main.cpp ${SOURCE})
target_link_libraries(project1 ${MBED_TLS})

add_executable(test_p1
        test/test-main.cpp
        test/test-impl.cpp
        ${SOURCE}
        )
target_link_libraries(test_p1 ${MBED_TLS})

#testing files
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/long.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/out.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/no_permissions.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupted.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupt1.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/corrupt2.txt ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

add_test(test_p1_run test_p1)

