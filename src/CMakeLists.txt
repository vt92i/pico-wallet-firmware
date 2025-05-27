# CMakeLists.txt for the Pico Wallet project

add_executable(${PROJECT_NAME})

# Add source files to the executable target.
target_sources(${PROJECT_NAME} PRIVATE pico_wallet.c usb_descriptors.c apdu.c
                                       apdu_utils.c smartcard.c)

# Add the include directory for header files.
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# Link required libraries for the project.
target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE pico_stdlib # Standard Pico SDK library
          pico_unique_id # Library for unique device ID
          pico_mbedtls # mbedTLS for cryptographic operations
          pico_flash # Flash memory library
          pico_multicore # Multicore support
          hardware_i2c # I2C hardware support
          hardware_flash # Flash memory support
          bip # BIP (Bitcoin Improvement Proposals) library
          # pico_async_context_freertos # Async context with FreeRTOS
          FreeRTOS-Kernel-Heap4 # FreeRTOS heap implementation
          tinyusb_device # TinyUSB device stack
          tinyusb_board # TinyUSB board support
          ssd1306 # SSD1306 OLED display driver
)

# USB and UART configuration.
pico_enable_stdio_usb(${PROJECT_NAME} 0)
pico_enable_stdio_uart(${PROJECT_NAME} 1)

# Add extra outputs (e.g., UF2, bin, hex files).
pico_add_extra_outputs(${PROJECT_NAME})
