# CMakeLists.txt for the Pico Wallet project

add_executable(${PROJECT_NAME})

# Add source files to the executable target.
target_sources(
  ${PROJECT_NAME}
  PRIVATE main.c
          apdu/apdu_dispatch.c
          apdu/apdu_utils.c
          apdu/commands/command_hash.c
          apdu/commands/command_wallet.c
          bip/bip39.c
          bip/bip32.c
          bip/bip84.c
          smartcard/smartcard.c
          tasks/tasks.c
          usb/usb_descriptors.c
          utils/flash.c)

# Add the include directory for header files.
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
          ${CMAKE_CURRENT_SOURCE_DIR}/apdu
          ${CMAKE_CURRENT_SOURCE_DIR}/apdu/commands
          ${CMAKE_CURRENT_SOURCE_DIR}/bip
          ${CMAKE_CURRENT_SOURCE_DIR}/smartcard
          ${CMAKE_CURRENT_SOURCE_DIR}/tasks
          ${CMAKE_CURRENT_SOURCE_DIR}/usb
          ${CMAKE_CURRENT_SOURCE_DIR}/utils)

# Link required libraries for the project.
target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE pico_stdlib
          pico_unique_id
          pico_mbedtls
          pico_flash
          pico_multicore
          hardware_i2c
          hardware_flash
          hardware_xip_cache
          FreeRTOS-Kernel-Heap4
          tinyusb_device
          tinyusb_board
          ssd1306)

# USB and UART configuration.
pico_enable_stdio_usb(${PROJECT_NAME} 0)
pico_enable_stdio_uart(${PROJECT_NAME} 1)

# Add extra outputs (e.g., UF2, bin, hex files).
pico_add_extra_outputs(${PROJECT_NAME})
