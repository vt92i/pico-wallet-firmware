/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Ha Thach (tinyusb.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "usb_descriptors.h"

#include "bsp/board_api.h"

//--------------------------------------------------------------------+
// Device Descriptor
//--------------------------------------------------------------------+

#define USB_VID 0x2E8A  // Raspberry Pi
#define USB_PID 0x10D8
#define USB_BCD 0x0200  // USB 2.0

tusb_desc_device_t const desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = USB_BCD,
    .bDeviceClass = 0xEF,     // Miscellaneous Device Class
    .bDeviceSubClass = 0x02,  // Common Class
    .bDeviceProtocol = 0x01,  // Interface Association Descriptor
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,

    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,

    .bNumConfigurations = 0x01,
};

uint8_t const* tud_descriptor_device_cb(void) { return (uint8_t const*)&desc_device; }

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

enum { ITF_NUM_CDC = 0, ITF_NUM_CDC_DATA, ITF_NUM_TOTAL };

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)

#define EPNUM_CDC_NOTIF  0x81  // CDC Notification Endpoint
#define EPNUM_CDC_OUT    0x02  // CDC Data OUT Endpoint
#define EPNUM_CDC_IN     0x82  // CDC Data IN Endpoint

uint8_t const desc_configuration[] = {
    // Config number, interface count, string index, total length, attribute, power in mA
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),

    // CDC: Control Interface
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, EPNUM_CDC_NOTIF, 8, EPNUM_CDC_OUT, EPNUM_CDC_IN, CFG_TUD_CDC_EP_BUFSIZE),
};

uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  return desc_configuration;
}

// Device only supports full-speed, so return NULL to indicate "not supported"
uint8_t const* tud_descriptor_device_qualifier_cb(void) { return NULL; }

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

enum {
  STRID_LANGID = 0,
  STRID_MANUFACTURER,
  STRID_PRODUCT,
  STRID_SERIAL,
  STRID_CDC_INTERFACE,
};

const char* const string_desc_arr[] = {
    (const char[]){0x09, 0x04},  // English (0x0409)
    "Raspberry Pi",              // Manufacturer
    "Pico Wallet",               // Product
    NULL,                        // Serial
    "CDC Interface"              //  CDC Interface
};

static uint16_t _desc_str[32 + 1];

uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  size_t chr_count;

  switch (index) {
    case STRID_LANGID:
      memcpy(&_desc_str[1], string_desc_arr[0], 2);
      chr_count = 1;
      break;

    case STRID_SERIAL:
      chr_count = board_usb_get_serial(_desc_str + 1, 32);
      break;

    default:
      // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
      // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

      if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) return NULL;

      const char* str = string_desc_arr[index];

      // Cap at max char
      chr_count = strlen(str);
      size_t const max_count = sizeof(_desc_str) / sizeof(_desc_str[0]) - 1;  // -1 for string type
      if (chr_count > max_count) chr_count = max_count;

      // Convert ASCII string into UTF-16
      for (size_t i = 0; i < chr_count; i++) {
        _desc_str[1 + i] = str[i];
      }
      break;
  }

  // first byte is length (including header), second byte is string type
  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));

  return _desc_str;
}
