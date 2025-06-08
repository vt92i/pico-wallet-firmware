add_library(mpack STATIC mpack.c)

target_include_directories(mpack PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
