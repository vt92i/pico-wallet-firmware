#ifndef _TASKS_H_
#define _TASKS_H_

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"

#define LCD_SDA_PIN  PICO_DEFAULT_I2C_SDA_PIN
#define LCD_SCL_PIN  PICO_DEFAULT_I2C_SCL_PIN
#define BUTTON_PIN   16

#define QUEUE_LENGTH 8

extern QueueHandle_t usb_rx_queue, usb_tx_queue;
extern QueueHandle_t smartcard_rx_queue, smartcard_tx_queue;
extern QueueHandle_t flash_rx_queue;

#endif /* _TASKS_H_ */
