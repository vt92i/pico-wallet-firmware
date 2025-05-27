#pragma once

#include "hardware/flash.h"

#define FLASH_SIZE          (PICO_FLASH_SIZE_BYTES)  // 4 MiB
#define FLASH_STORAGE_SIZE  (4 * 1024)               // 4 KiB
#define FLASH_TARGET_OFFSET (FLASH_SIZE - FLASH_STORAGE_SIZE)

extern const uint8_t* flash_target_contents;

void __not_in_flash_func(call_flash_range_erase)(void* param);
void __not_in_flash_func(call_flash_range_program)(void* param);
