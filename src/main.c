#include "FreeRTOS.h"  // IWYU pragma: keep
#include "queue.h"
#include "task.h"

#include "bsp/board_api.h"
#include "rpc/rpc.h"
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

// static void memory_watcher(void* pvParams) {
//   (void)pvParams;
//
//   for (;;) {
//     printf("=== FreeRTOS Memory Info ===\n");
//     printf("Heap size:           %u bytes\n", configTOTAL_HEAP_SIZE);
//     printf("Current free heap:   %u bytes\n", (unsigned)xPortGetFreeHeapSize());
//     printf("Minimum ever free:   %u bytes\n", (unsigned)xPortGetMinimumEverFreeHeapSize());
//     printf("============================\n\n");
//
//     vTaskDelay(pdMS_TO_TICKS(1000));
//   }
// }

static void runit(void) {
  board_init();
  tusb_init(void);
}

int main(void) {
  runit();

  usb_rx_queue = xQueueCreate(4, sizeof(rpc_buffer_t));
  usb_tx_queue = xQueueCreate(4, sizeof(rpc_buffer_t));

  smartcard_rx_queue = xQueueCreate(1, sizeof(smartcard_request_t));
  smartcard_tx_queue = xQueueCreate(1, sizeof(smartcard_response_t));

  flash_rx_queue = xQueueCreate(1, sizeof(flash_buffer_t));

  // xTaskCreate(memory_watcher, "Memory Watcher", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 16UL, NULL);

  xTaskCreate(flash_writer_task, "Flash Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 12UL, NULL);

  xTaskCreate(usb_reader_task, "USB Reader Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);
  xTaskCreate(usb_writer_task, "USB Writer Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 10UL, NULL);

  xTaskCreate(rpc_handler_task, "RPC Handler Task", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 8UL, NULL);
  xTaskCreate(smartcard_handler_task, "Smartcard Handler Task", configMINIMAL_STACK_SIZE * 2, NULL,
              tskIDLE_PRIORITY + 6UL, NULL);

  // Start FreeRTOS scheduler
  vTaskStartScheduler();

  /* ---------------------------------------------------------+
   * Should never reach here, as the scheduler will take over.
   * If for some reason it does, then you fucked up something.
   * ---------------------------------------------------------+*/
  for (;;);
}
