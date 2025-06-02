#ifndef _FLASH_H_
#define _FLASH_H_

#include "hardware/flash.h"

#define FLASH_SIZE          (PICO_FLASH_SIZE_BYTES)  // Total flash size
#define FLASH_STORAGE_SIZE  (4 * 1024)               // 4 KiB for storage
#define FLASH_TARGET_OFFSET (FLASH_SIZE - FLASH_STORAGE_SIZE)

const uint8_t* flash_target_contents = (const uint8_t*)(XIP_BASE + FLASH_TARGET_OFFSET);

void __not_in_flash_func(call_flash_range_erase)(void* param);
void __not_in_flash_func(call_flash_range_program)(void* param);

#endif /* _FLASH_H_ */
