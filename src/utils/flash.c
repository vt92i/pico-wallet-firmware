#include "flash.h"

const uint8_t* flash_target_contents = (const uint8_t*)(XIP_BASE + FLASH_TARGET_OFFSET);

void __not_in_flash_func(call_flash_range_erase)(void* param) {
  uint32_t offset = (uint32_t)param;
  flash_range_erase(offset, FLASH_SECTOR_SIZE);
}

void __not_in_flash_func(call_flash_range_program)(void* param) {
  uint32_t offset = ((uintptr_t*)param)[0];
  const uint8_t* data = (const uint8_t*)((uintptr_t*)param)[1];
  flash_range_program(offset, data, FLASH_PAGE_SIZE);
}
