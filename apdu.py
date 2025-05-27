import hid

VID = 0x2E8A  # Raspberry Pi Vendor ID
PID = 0x10D8  # Pico Wallet Product ID


def main():
    """
    Main function to communicate with a USB HID device using APDU commands.

    - Opens the device using the specified Vendor ID (VID) and Product ID (PID).
    - Sends a 64-byte APDU command to the device.
    - Reads and prints the response from the device.
    - Handles exceptions and ensures the device is closed properly.
    """
    try:
        # Open your device by Vendor ID and Product ID
        # You can also use the device path if you know it
        device = hid.Device(vid=VID, pid=PID)

        print("Device opened successfully!")

        # Example data to send (64 bytes)
        rest = []
        for i in range(1, 65):
            rest.append(i % 256)  # Fill with some data, e.g., 0x01, 0x02, ..., 0x3F

        # data_out = bytes([0x00] + rest)  # APDU command with 64 bytes of data

        data_out = bytes([0x00, 0x80, 0x00, 0xF2, 0xF4, 0x01, 0x01])

        # Send data to the device (host to device)
        device.write(data_out)
        print(
            "Sent:",
            " ".join(f"0x{byte:02x}" for byte in data_out),
            f"({len(data_out)} bytes)",
        )

        # Read response (device to host)
        data_in = device.read(64, timeout=5000)
        if data_in:
            print(
                "Received:",
                " ".join(f"0x{byte:02X}" for byte in data_in),
                f"({len(data_in)} bytes)",
            )
        else:
            print("No data received.")

        device.close()

    except Exception as e:
        print(f"Failed to communicate with the device: {e}")


if __name__ == "__main__":
    main()
