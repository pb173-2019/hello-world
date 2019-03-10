add_subdirectory(client)
add_subdirectory(server)

#add shared as library
file(GLOB shared_src "./shared/*.h" "./shared/*.cpp")
add_library(shared ${shared_src})
#target_include_directories(shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/shared)