add_executable(${PROJECT_NAME})

file(GLOB_RECURSE BIP_SOURCES CONFIGURE_DEPENDS bip/*.c)
file(GLOB_RECURSE RPC_SOURCES CONFIGURE_DEPENDS rpc/*.c)
file(GLOB_RECURSE SMARTCARD_SOURCES CONFIGURE_DEPENDS smartcard/*.c)
file(GLOB_RECURSE TASK_SOURCES CONFIGURE_DEPENDS tasks/*.c)
file(GLOB_RECURSE USB_SOURCES CONFIGURE_DEPENDS usb/*.c)
file(GLOB_RECURSE UTILS_SOURCES CONFIGURE_DEPENDS utils/*.c)

set(SOURCES
    main.c
    ${BIP_SOURCES}
    ${RPC_SOURCES}
    ${SMARTCARD_SOURCES}
    ${TASK_SOURCES}
    ${USB_SOURCES}
    ${UTILS_SOURCES})

foreach(SOURCE IN LISTS SOURCES)
  set_source_files_properties(
    ${SOURCE}
    PROPERTIES
      COMPILE_FLAGS
      "-Wall -Wextra -Wpedantic -Wconversion -Wfloat-conversion -Wsign-conversion -Werror"
  )
endforeach()

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})

target_include_directories(
  ${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                          ${PROJECT_SOURCE_DIR}/include)

set(CORE_LIBS
    pico_stdlib
    pico_unique_id
    pico_mbedtls
    pico_flash
    hardware_flash
    hardware_xip_cache
    FreeRTOS-Kernel-Heap4
    tinyusb_device
    tinyusb_board)

set(EXTERNAL_LIBS micro_ecc)

target_link_libraries(${PROJECT_NAME} PRIVATE ${CORE_LIBS} ${EXTERNAL_LIBS})

pico_enable_stdio_usb(${PROJECT_NAME} 0)
pico_enable_stdio_uart(${PROJECT_NAME} 1)

pico_add_extra_outputs(${PROJECT_NAME})
