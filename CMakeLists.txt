cmake_minimum_required(VERSION 3.31)

set(PROJECT_NAME pico_wallet)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PICO_BOARD pico2)
set(PICO_PLATFORM rp2350-arm-s)

include(pico_sdk_import.cmake)
include(FreeRTOS_Kernel_import.cmake)

project(${PROJECT_NAME} C CXX ASM)

pico_sdk_init()

include(FetchContent)

FetchContent_Declare(
  micro_ecc
  GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
  GIT_TAG v1.1)
FetchContent_MakeAvailable(micro_ecc)

add_library(micro_ecc STATIC ${micro_ecc_SOURCE_DIR}/uECC.c
                             ${micro_ecc_SOURCE_DIR}/uECC.h)
target_include_directories(micro_ecc PUBLIC ${micro_ecc_SOURCE_DIR})

add_subdirectory(src)
