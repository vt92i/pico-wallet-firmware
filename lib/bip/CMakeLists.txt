add_library(bip bip39.c)

target_link_libraries(bip PRIVATE pico_mbedtls)
target_include_directories(bip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
