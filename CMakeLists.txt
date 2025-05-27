# Minimum required version of CMake
cmake_minimum_required(VERSION 3.31)

# Set the project name
set(PROJECT_NAME pico_wallet)

# Specify the target Pico board
set(PICO_BOARD pico2)

# Specify the Pico platform
set(PICO_PLATFORM rp2350-arm-s)

# Import the Pico SDK
include(pico_sdk_import.cmake)

# Import the FreeRTOS Kernel
include(FreeRTOS_Kernel_import.cmake)

# Define the project and supported languages
project(${PROJECT_NAME} C CXX ASM)

# Set the C and C++ standard versions
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialize the Pico SDK
pico_sdk_init()

# Add the main source directory
add_subdirectory(src)

# Add the SSD1306 library directory
add_subdirectory(lib/ssd1306)

# Add the BIP library directory
add_subdirectory(lib/bip)
