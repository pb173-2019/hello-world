add_library(sqlite3 shell.c sqlite3.h sqlite3.c sqlite3ext.h)
set_target_properties(sqlite3 PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(sqlite3 ${CMAKE_DL_LIBS})