#pragma once

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

#define LCD_SDA_PIN  PICO_DEFAULT_I2C_SDA_PIN
#define LCD_SCL_PIN  PICO_DEFAULT_I2C_SCL_PIN
#define BUTTON_PIN   16

#define QUEUE_LENGTH 8
