#include "hardware/gpio.h"
#include "hardware/i2c.h"

#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "bsp/board_api.h"
#include "rpc/rpc.h"
#include "smartcard/commands/smartcard_commands.h"
#include "smartcard/smartcard.h"
#include "tasks/flash/flash_writer_task.h"
#include "tasks/rpc/rpc_handler_task.h"
#include "tasks/smartcard/smartcard_handler_task.h"
#include "tasks/usb/usb_reader_task.h"
#include "tasks/usb/usb_writer_task.h"

#if (configCHECK_FOR_STACK_OVERFLOW > 0)
void vApplicationStackOverflowHook(TaskHandle_t xTask, char* pcTaskName) {
  (void)xTask;
  taskDISABLE_INTERRUPTS();
  printf("Stack overflow in task: %s\n", pcTaskName);
  for (;;);
}
#endif /* configCHECK_FOR_STACK_OVERFLOW > 0 */

#define LCD_SDA_PIN PICO_DEFAULT_I2C_SDA_PIN
#define LCD_SCL_PIN PICO_DEFAULT_I2C_SCL_PIN
#define BUTTON_PIN  16

static void runit(void) {
  board_init();
  tusb_init(void);

  // Initialize I2C
  i2c_init(i2c_default, 400 * 1000);  // 400 kHz I2C speed
  gpio_set_function(LCD_SDA_PIN, GPIO_FUNC_I2C);
  gpio_set_function(LCD_SCL_PIN, GPIO_FUNC_I2C);
  gpio_pull_up(LCD_SCL_PIN);
  gpio_pull_up(LCD_SDA_PIN);

  // Initialize  GPIO
  gpio_init(BUTTON_PIN);
  gpio_set_function(BUTTON_PIN, GPIO_FUNC_SIO);
  gpio_set_dir(BUTTON_PIN, GPIO_IN);
  gpio_pull_up(BUTTON_PIN);
}

int main(void) {
  runit();

  usb_rx_queue = xQueueCreate(4, sizeof(rpc_buffer_t));
  usb_tx_queue = xQueueCreate(4, sizeof(rpc_buffer_t));

  smartcard_rx_queue = xQueueCreate(1, sizeof(smartcard_command_t));
  smartcard_tx_queue = xQueueCreate(1, sizeof(smartcard_response_t));

  flash_rx_queue = xQueueCreate(1, BIP39_SEED_SIZE);

  xTaskCreate(flash_writer_task, "Flash Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 12UL, NULL);

  xTaskCreate(usb_reader_task, "USB Reader Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);
  xTaskCreate(usb_writer_task, "USB Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);

  xTaskCreate(rpc_handler_task, "RPC Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 8UL, NULL);
  xTaskCreate(smartcard_handler_task, "Smartcard Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 6UL,
              NULL);

  // Start FreeRTOS scheduler
  vTaskStartScheduler();

  /* ---------------------------------------------------------+
   * Should never reach here, as the scheduler will take over.
   * If for some reason it does, then you fucked up something.
   * ---------------------------------------------------------+*/
  for (;;);
}
